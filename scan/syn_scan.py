"""
************************* SYN 扫描 *******************************
原理：构造syn数据包（三次握手的第一个数据包）,等待对方回复数据包,数据包的flag中ack和syn为1则说明端口开放
     （通过抓包可以看到，两个数据包过后，这边会自动回复一个rst包

主要模块： 1、构造ip头
         2、构造tcp头
         3、通过多线程的方式进行SYN扫描 （多线程失败）

待解决问题： 1、多线程失败, 会出现端口判断不准确情况, 这里我认为是, recvfrom接受数据紊乱？ 一个线程可能抢了别的线程的数据？ 尝试bind依旧不行？
              但有时候会多出端口,比如只有3个端口开放，但却扫出了5个端口开放？？？ 去掉多线程后恢复正常
              在非多线程的情况下，同时运行两个会出现同样的问题, 这里原始套接字会捕捉所有发回的包？不管端口？
           2、目前只能在Linux下已root权限运行, Windows下能否实现运行, 查询中发现有说windows可以尝试调用winpcap来运行
           3、被防火墙拦截,暂时没什么办法,nmap也会被拦,tcp connect, tcp sck, tcp fon都会被拦截

一些知识点：
    网络字节顺序NBO(Network Byte Order): 按从高到低的顺序存储，在网络上使用统一的网络字节顺序，可以避免兼容性问题。
    主机字节顺序(HBO，Host Byte Order): 不同的机器HBO不相同，与CPU设计有关，数据的顺序是由cpu决定的,而与操作系统无关。
    如 Intel x86结构下, short型数0x1234表示为34 12, int型数0x12345678表示为78 56 34 12
    如 IBM power PC结构下, short型数0x1234表示为12 34, int型数0x12345678表示为12 34 56 78
"""
import socket
import sys
import threading
import random
from struct import *

open_port_list = [] # 全局变量，用于记录开放的端口


def checksum(msg):
    """计算校验和"""
    # 1、  把校验和字段置为0；
    # 2、  对IP头部中的每16bit进行二进制求和；
    # 3、  如果和的高16bit不为0，则将和的高16bit和低16bit反复相加，直到和的高16bit为0，从而获得一个16bit的值；
    # 4、  将该16bit的值取反，存入校验和字段。

    s = 0
    # 每次取2个字节
    for i in range(0,len(msg),2):
        w = ((msg[i]) << 8) + ((msg[i+1])) # 将2个字节组合成一个16bit的数
        s = s+w # 将16bit的数循环加起来
    # 如果高16bit不为0，就将高16bit与低16bit相加，直至高16bit变为0
    while (s>>16) != 0:
        s = (s>>16) + (s & 0xffff) # 将高16bit和低16bit向加起来
    s = ~s & 0xffff # 将s取反作为校验和
    return s

def CreateSocket(source_ip,dest_ip):
    """创造原始套接字"""
    try:
        # 创建原始套接字
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) # 第三个参数用来指明所要接收的协议包
        # 设置手工提供IP头部
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # 这里第一个参数设置为socket.IPPROTO_TCP会报错, 这里的原始套接字参数还是不是很理解,查了下IP_HDRINCL应该是IPPROTO_IP下的选项
        # 参考： https://blog.csdn.net/wawj522527/article/details/7867741
        s.settimeout(1) # 设置超时, 这里设置的是1秒
    except:
        print ('Socket create error: ',sys.exc_info()[0],'message: ',sys.exc_info()[1])
        sys.exit()

    return s


def CreateIpHeader(source_ip, dest_ip):
    """构造ip头"""

    # ip 头部各参数填充
    version = 4 # 4位  版本  一般0100（IPv4）
    headerlen = 5 # 4位 数据包头部长度 无可选项为20（最小值）
    tos = 0 # 8位 服务类型
    tot_len = 20 + 20 # 16位 ip包总长，这里要包含数据部分 ip头（20字节） + tcp头（20字节） + 数据部分
    id = random.randrange(18000,65535,1) # 16位 ip标识符 主要用于包需要拆分时使用 和Flags和Fragment Offest字段联合使用
    frag_off = 0 # 3位+13位（这里合并了下） Flags: 3位 Fragment Offset: 13位 （主要还是分包时用）
    ttl = 255 # 8位 TTL 没什么好说的都懂
    protocol = socket.IPPROTO_TCP # 8位 标识了上层所使用的协议
    check = 0 # 16位 头部校验, 这里先置为0, 内核会自动计算正确的校验和去填充。
    saddr = socket.inet_aton ( source_ip ) # 32位 源ip地址头填充  inet_aton: 转换IPV4地址字符串成为32位打包的二进制格式
    daddr = socket.inet_aton ( dest_ip ) # 32位 目标ip地址
    hl_version = (version << 4) + headerlen # 将版本和数据包头部长度合并在一起
    ip_header = pack('!BBHHHBBH4s4s', hl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

    return ip_header

def create_tcp_syn_header(source_ip, dest_ip, dest_port):
    """构造tcp头部"""

    # tcp 头部选项
    source = random.randrange(32000,62000,1) # 16位 随机化一个源端口,作为源端口
    seq = 0 # 32位 某个主机开启一个TCP会话时,他的初始序列号是随机的
    ack_seq = 0  # 32位 确认序列号

    doff = 5 # 4位 偏移,与ip头类似,表明数据距包头有多少个32位（也就是数据包头长度,最小20字节,5个32位）
    
    # 6位 tcp flags ：  URG, ACK, SYN, RST, PSH, FIN
    fin = 0 # 关闭连接
    syn = 1 # 建立连接
    rst = 0 # 连接重置
    psh = 0 # 有无有DATA数据传输
    ack = 0 # 响应
    urg = 0 # 紧急指针是否有效

    window = socket.htons (8192) # 16位 窗口字段,用来控制对方发送的数据量，单位为字节,最大窗口大小   htons:将主机字节顺序转换成网络字节顺序(16bit)
    check = 0  # 16位 校验和 这里先设置为0,用于后面计算正确的校验和.
    urg_ptr = 0 # 16位 紧急指针
    offset_res = (doff << 4) + 0 # 10位 偏移与保留位合并, 偏移4位, 保留位6位
    tcp_flags = fin + (syn<<1) + (rst<<2) + (psh<<3) + (ack<<4) + (urg<<5) # 合并flag位
    tcp_header = pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

    # 包括首部和数据这两部分,在计算检验和时,要在TCP报文段的前面加上12字节的伪首部
    # 伪头部选项
    source_address = socket.inet_aton( source_ip ) # 源IP地址
    dest_address = socket.inet_aton( dest_ip ) # 目标IP地址
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length) # 伪头部
    psh = psh + tcp_header
    tcp_checksum = checksum(psh) # 计算校验和

    # 重新打包TCP头部，并填充正确地校验和
    tcp_header = pack('!HHLLBBHHH', source, dest_port, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)
    return tcp_header


def range_scan(source_ip, dest_ip, port) :
    syn_ack_received = -1   # 返回值

    dest_port = port
    s = CreateSocket(source_ip, dest_ip) # 创建原始套接字
    ip_header = CreateIpHeader(source_ip, dest_ip) # 创建IP头
    tcp_header = create_tcp_syn_header(source_ip, dest_ip,dest_port) # 创建TCP头
    packet = ip_header + tcp_header # 生成要发送的包

    s.sendto(packet, (dest_ip, dest_port)) # 测试了下这里必须要用sendto, 用send会报错

    try: # 如果这里recv超时,就会触发异常
        data = s.recvfrom(1024) # 这里用recv也完全没问题
    except Exception as e:
        print(e)
        return
    # print(data)

    data = data [0]

    # 下面这堆数据完全可以不用计算，不会影响定位flag值
    ip_header_len = ((data[0]) & 0x0f) * 4 # 确定ip数据包长度, 这里&0x0f取到后4位的长度,然后*4将长度单位转化为字节（IHL= IP头部长度（单位为bit）/(8*4)）
    ip_header_ret = data[0: ip_header_len - 1] # ip包头数据
    tcp_header_len = ((data[32]) & 0xf0)>>2 # 这就是取到数值，也就是tcp包头长度
    tcp_header_ret = data[ip_header_len:ip_header_len+tcp_header_len - 1] # tcp包头长度

    if (tcp_header_ret[13]) == 0x12: # SYN/ACK flags 这里取到的8位 前两位为保留值,我们希望syn值和ack值为1,也就是第4位和第7位要为1,希望得到的结果：00010010
        open_port_list.append(port)



def main():
    """main"""
    ipsource = '192.168.1.8' # 源IP
    ipdest = '192.168.1.66' # 目标IP
    scan_ports = [135, 139, 250, 445, 600, 123] # 待扫描端口

    for i in scan_ports:
        range_scan(ipsource, ipdest, i)

    for i in open_port_list:
        print('[+] %d/tcp open'%i)

    print('[:-)] The SYN scan is complete!')


if __name__ == '__main__':
    main()
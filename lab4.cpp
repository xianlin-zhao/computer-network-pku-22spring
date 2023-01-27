/*
* THIS FILE IS FOR TCP TEST
*/

/*
struct sockaddr_in {
        short   sin_family;
        u_short sin_port;
        struct  in_addr sin_addr;
        char    sin_zero[8];
};
*/

#include "sysInclude.h"
#include <map>

enum stateInfo {CLOSED, SYNSENT, ESTABLISHED, FINWAIT1, FINWAIT2, TIMEWAIT};  // TCP状态机的6种状态
#define FAKEHEADLEN 12  // 伪首部是12个字节
#define TCPHEADLEN 20  // TCP首部是20个字节（这个实验不考虑选项和填充字段）
#define MAXHEADLEN 64  // TCP首部字节数的最大值
#define TIMEOUT 3000  // 调用waitIpPacket函数时的一个参数（指导书里不给解释，随便设的）
// TCP首部的几个标志位
#define FIN 0x1
#define SYN 0x2
#define ACK 0x10

int gSrcPort = 2007;
int gDstPort = 2006;
int gSeqNum = 1;  // 起始序列号（指导书上是0，但那样会报错）
int gAckNum = 0;
int gSockfd = 0;  // 套接口描述符，每次新分配一个，就加1

/*
 * 保存TCP连接信息的数据结构
 * 记录两端的IP地址和端口号、连接状态、待发分组的seq和ack，套接口描述符
 */
class tcb
{
    public:
    unsigned int srcIP, dstIP;
    unsigned short srcPort, dstPort;
    stateInfo state;
    unsigned int seq;
    unsigned int ack;
    int sockfd;

    tcb() // 默认构造函数。最初始的状态是CLOSED，sockfd每次会加1
    {
        srcIP = getIpv4Address();
        dstIP = getServerIpv4Address();
        srcPort = gSrcPort;
        dstPort = gDstPort;
        state = CLOSED;
        seq = gSeqNum;
        ack = gAckNum;
        sockfd = gSockfd++;
    }
};

tcb *nowTcb;  // 正在处理的tcb
map<int, tcb *> sockets;  // sockfd与tcb的映射

extern void tcp_DiscardPkt(char *pBuffer, int type);

extern void tcp_sendReport(int type);

extern void tcp_sendIpPkt(unsigned char *pData, UINT16 len, unsigned int  srcAddr, unsigned int dstAddr, UINT8	ttl);

extern int waitIpPacket(char *pBuffer, int timeout);

extern unsigned int getIpv4Address();

extern unsigned int getServerIpv4Address();

// 计算TCP头部校验和，后三个参数用于构造伪首部
unsigned short checksum(char *buffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr)
{
    unsigned int sum = 0;
    char *fakeHead = (char *) malloc(FAKEHEADLEN);  // 伪首部有12字节，0-3和4-7字节分别是源IP和目的IP
    ((unsigned int *) fakeHead)[0] = srcAddr;
    ((unsigned int *) fakeHead)[1] = dstAddr;
    fakeHead[8] = 0;  // 保留字节，置0
    fakeHead[9] = 0x6;  // 传输层协议号，TCP是6
    ((unsigned short *) fakeHead)[5] = htons(len);  // 最后2字节是TCP长度（首部+数据） 
    for (int i = 0; i < FAKEHEADLEN / 2; i++) {  // 先对伪首部计算
        sum += ((unsigned short *) fakeHead)[i];
        sum = (sum >> 16) + (sum & 0xffff);
    }

    for (int i = 0; i < (len / 2); i++) {  // 与之前的实验一样，反码算术运算求和
        sum += ((unsigned short *) buffer)[i];
        sum = (sum >> 16) + (sum & 0xffff);
    }

    if (len & 1) {  // 总长度（按字节计）为奇数，因为要按照unsighed short类型计算，所以要补一个字节的0
        char padding[2] = {0};
        padding[0] = buffer[len - 1];
        sum += *((unsigned short *) padding);
        sum = (sum >> 16) + (sum & 0xffff);
    }
    
    free(fakeHead);
    return ~(unsigned short) sum;  // 把32位转成16位，最后取反
}

int stud_tcp_input(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr)
{
    char *buffer = (char *) malloc(len);
    memcpy(buffer, pBuffer, len);
    unsigned short sum = checksum(buffer, len, srcAddr, dstAddr);  // 第1步，检查校验和
    if (sum != 0)
        return -1;       

    // 第2步，字节序转换。按照TCP首部的格式，获取源和目的IP地址、端口号、seq、ack，都转换为主机序
    srcAddr = ntohl(srcAddr), dstAddr = ntohl(dstAddr); 
    unsigned short srcPort, dstPort;
    unsigned int seq, ack;
    srcPort = ntohs(((unsigned short *) buffer)[0]), dstPort = ntohs(((unsigned short *) buffer)[1]);
    seq = ntohl(((unsigned int *) buffer)[1]), ack = ntohl(((unsigned int *) buffer)[2]);

    // 源端口或目的端口错误，就丢弃报文
    if (srcPort != nowTcb->dstPort) {
        tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SRCPORT_ERROR);
        return -1;
    }
    if (dstPort != nowTcb->srcPort) {
        tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_DSTPORT_ERROR);
        return -1;
    }

    if (!nowTcb)
        return -1;
    if (ack != nowTcb->seq + 1) {  // 第3步，检查ack
        tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
        return -1;
    }  

    // 第4步，有限状态机处理，改seq和ack，转移状态。如有需要，调用output函数发送相应的TCP报文
    if (nowTcb->state == SYNSENT) {  // 原来是SYNSENT，现在收到了ACK，就应该完成第三次握手，发回ACK
        nowTcb->seq = ack, nowTcb->ack = seq + 1; 
        nowTcb->state = ESTABLISHED;
        stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, nowTcb->srcPort, nowTcb->dstPort, nowTcb->srcIP, nowTcb->dstIP);
    } else if (nowTcb->state == FINWAIT1) {  // 原来是FINWAIT1，现在收到了ACK。转到FINWAIT2状态
        nowTcb->state = FINWAIT2;
    } else if (nowTcb->state == FINWAIT2) {  // 原来是FINWAIT2，现在收到了服务器端的FIN报文，要发回ACK
        nowTcb->seq = ack, nowTcb->ack = seq + 1; 
        nowTcb->state = TIMEWAIT;
        stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, nowTcb->srcPort, nowTcb->dstPort, nowTcb->srcIP, nowTcb->dstIP);
    } else
        return -1;
	return 0;
}

void stud_tcp_output(char *pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr)
{
    if (!nowTcb)  // 用在第一个测试上，最开始没有tcb
        nowTcb = new tcb();
    char *buffer = (char *) malloc(len + TCPHEADLEN);  // 总长度是数据长度len+首部长度20字节
    memset(buffer, 0, len + TCPHEADLEN);
    memcpy(buffer + TCPHEADLEN, pData, len);  // 把数据内容先复制过来，我们只用填写首部各字段

    ((unsigned short *) buffer)[0] = htons(nowTcb->srcPort);
    ((unsigned short *) buffer)[1] = htons(nowTcb->dstPort);
    ((unsigned int *) buffer)[1] = htonl(nowTcb->seq);
    ((unsigned int *) buffer)[2] = htonl(nowTcb->ack);
    buffer[12] = (TCPHEADLEN / 4) << 4;  // 首部长度，以4字节为单位。在首部第12字节的高4位

    // 根据要发送的报文类型，设置标志字段。
    if (flag == PACKET_TYPE_SYN) {
        buffer[13] |= SYN;
        nowTcb->state = SYNSENT;
    } else if (flag == PACKET_TYPE_SYN_ACK) {
        buffer[13] |= (SYN | ACK);
    } else if (flag == PACKET_TYPE_ACK) {  // 这里不用状态转移了，在input函数里面已经转移过了
        buffer[13] |= ACK;
    } else if (flag == PACKET_TYPE_FIN) {
        buffer[13] |= FIN;       
    } else if (flag == PACKET_TYPE_FIN_ACK) {  // 指导书上说的有问题，四次挥手的最开始应该发FIN_ACK，而不是FIN
        buffer[13] |= (FIN | ACK);
        nowTcb->state = FINWAIT1;
    }

    ((unsigned short *) buffer)[7] = htons(1);  // 窗口大小，这个实验是“停等”，窗口就是1
    unsigned short sum = checksum(buffer, len + TCPHEADLEN, htonl(nowTcb->srcIP), htonl(nowTcb->dstIP));
    ((unsigned short *) buffer)[8] = sum;  // 最后算出校验和
    tcp_sendIpPkt((unsigned char *)buffer, len + TCPHEADLEN, nowTcb->srcIP, nowTcb->dstIP, 16);
    return;
}

/*
 * 创建新的TCB结构，构造函数中会分配套接口描述符
 * 然后把这对新的映射关系插入sockets中
 */
int stud_tcp_socket(int domain, int type, int protocol)
{
    tcb *newTcb = new tcb();
    int fd = newTcb->sockfd;
    sockets.insert(make_pair(fd, newTcb));
	return fd;
}

/*
 * 根据传入的参数，更改sockfd对应的TCB结构体中的目的IP地址和端口
 * 需要完成三次握手，先用output发SYN，然后等待对方回复ACK
 * 调用input接收对方回复的ACK，在input函数里顺便会发送ACK，以完成三次握手
 */
int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int addrlen)
{
    // 先在map里找到要操作的TCB。这套操作后面都会用
    map<int, tcb *>::iterator it;
    it = sockets.find(sockfd);
    if (it == sockets.end())
        return -1;
    nowTcb = it->second;
    
    nowTcb->dstPort = ntohs(addr->sin_port);  // 设置TCB中的目的端口、目的IP地址
    nowTcb->dstIP = ntohl(addr->sin_addr.s_addr);

    stud_tcp_output(NULL, 0, PACKET_TYPE_SYN, nowTcb->srcPort, nowTcb->dstPort, nowTcb->srcIP, nowTcb->dstIP);
    char *buffer = (char *) malloc(MAXHEADLEN);  // 回复的报文没有数据部分，分配MAXHEADLEN就足够了
    int len = waitIpPacket(buffer, TIMEOUT);
    if (len == -1)
        return -1;
    
    // 接收对方的ACK，在这个函数里也会回复ACK
    if (stud_tcp_input(buffer, len, htonl(nowTcb->dstIP), htonl(nowTcb->srcIP)) < 0)
        return -1;
    return 0;
}

/*
 * 判断是否处于ESTABLISHED状态，如果是，发送数据类型的报文
 * 发送完以后，还要准备接收ACK，这里就不用input函数了，因为和input的处理方式不太一样
 */
int stud_tcp_send(int sockfd, const unsigned char *pData, unsigned short datalen, int flags)
{
    map<int, tcb *>::iterator it;
    it = sockets.find(sockfd);
    if (it == sockets.end())
        return -1;
    nowTcb = it->second;

    if (nowTcb->state == ESTABLISHED) {
        char *sendData = (char *) malloc(datalen);
        memcpy(sendData, pData, datalen);
        stud_tcp_output(sendData, datalen, PACKET_TYPE_DATA, nowTcb->srcPort, nowTcb->dstPort, nowTcb->srcIP, nowTcb->dstIP);
        char *buffer = (char *) malloc(MAXHEADLEN);
        int len = waitIpPacket(buffer, TIMEOUT);
        if (len == -1)
            return -1;
        
        unsigned int seq = ntohl(((unsigned int *) buffer)[1]);
        unsigned int ack = ntohl(((unsigned int *) buffer)[2]);
        if (ack != nowTcb->seq + datalen)  // 这个判断与input不一样，ack应该是seq加上数据长度
            return -1;
        nowTcb->seq = ack, nowTcb->ack = seq + 1;
    } else
        return -1;
	return 0;
}

/*
 * 判断是否处于ESTABLISHED状态，接收数据，拷贝到指定的缓冲区
 * 这里也不调用input了，没必要。改一下seq和ack即可，然后回复ACK
 */
int stud_tcp_recv(int sockfd, unsigned char *pData, unsigned short datalen, int flags)
{
    map<int, tcb *>::iterator it;
    it = sockets.find(sockfd);
    if (it == sockets.end())
        return -1;
    nowTcb = it->second;

    if (nowTcb->state == ESTABLISHED) {
        char *recvData = (char *) malloc(1100);
        int len = waitIpPacket(recvData, TIMEOUT);  // 接收服务器发送的数据
        if (len == -1)
            return -1;
        int headLen = ((recvData[12] & 0xf0) >> 4) * 4;  // 获取首部长度（以4字节为单位）
        memcpy(pData, recvData + headLen, len - headLen);
        
        // 更新TCB中的seq和ack，准备回复ACK（output发送时填到首部），ack和前面不同，应该是seq加上本次收到的数据长度
        unsigned int seq = ntohl(((unsigned int *) recvData)[1]);
        unsigned int ack = ntohl(((unsigned int *) recvData)[2]);
        nowTcb->seq = ack, nowTcb->ack = seq + len - headLen;  // 数据长度并不是参数datalen
        stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, nowTcb->srcPort, nowTcb->dstPort, nowTcb->srcIP, nowTcb->dstIP);
    } else
        return -1;
	return 0;
}

/* 
 * 先判断状态，如果是ESTABLISHED，就需要完成四次挥手
 * 即自己先发FIN_ACK，然后等待对方回ACK。接着对方会发FIN_ACK，接收后，自己再回复ACK
 * 这样就完成了四次挥手。最后还要清除与sockfd相关的一切（sockets, nowTcb）
 */
int stud_tcp_close(int sockfd)
{
    map<int, tcb *>::iterator it;
    it = sockets.find(sockfd);
    if (it == sockets.end())
        return -1;
    nowTcb = it->second;

    if (nowTcb->state == ESTABLISHED) {  // 自己先发FIN_ACK，再收2次对方的报文，第2次收的时候，input函数会顺便发ACK
        stud_tcp_output(NULL, 0, PACKET_TYPE_FIN_ACK, nowTcb->srcPort, nowTcb->dstPort, nowTcb->srcIP, nowTcb->dstIP);
        char *buffer = (char *) malloc(MAXHEADLEN);
        int len = waitIpPacket(buffer, TIMEOUT);
        if (len == -1)
            return -1;
        if (stud_tcp_input(buffer, len, htonl(nowTcb->dstIP), htonl(nowTcb->srcIP)) < 0)
            return -1;
        
        len = waitIpPacket(buffer, TIMEOUT);
        if (len == -1)
            return -1;
        if (stud_tcp_input(buffer, len, htonl(nowTcb->dstIP), htonl(nowTcb->srcIP)) < 0)
            return -1;
    }

    // 从map里删掉，再把这个TCB结构体删掉，nowTcb置为NULL。之后如果某函数要操作某个TCB，函数的开头会自动把nowTcb指向它
    sockets.erase(sockfd);
    delete nowTcb;   
    nowTcb = NULL;
	return 0;
}

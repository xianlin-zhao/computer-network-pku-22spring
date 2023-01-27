/*
* THIS FILE IS FOR IP TEST
*/
// system support
#include "sysInclude.h"
#include <string.h>
using namespace std;

extern void ip_DiscardPkt(char* pBuffer,int type);

extern void ip_SendtoLower(char*pBuffer,int length);

extern void ip_SendtoUp(char *pBuffer,int length);

extern unsigned int getIpv4Address();

// implemented by students

unsigned short checksum(unsigned short *buffer, int length) // 计算校验和，来自ppt
{
    unsigned int sum = 0;
    for (int i = 0; i < length; i++)
    {
        sum += ntohs(buffer[i]);
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return ~(unsigned short) sum;
}

int stud_ip_recv(char *pBuffer,unsigned short length)
{
    char *buffer = (char *) malloc(length);
    memcpy(buffer, pBuffer, length);  // 保存pBuffer的副本，防止指针乱指

    unsigned short version = (buffer[0] >> 4) & (0xf); // 最初的4位是版本号
    if (version != 4){ // 不是IPV4
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
        return 1;
    }
    
    unsigned short headLength = buffer[0] & (0xf);  // 4-7位是头部长度，以4字节为单位
    if (headLength <= 4) {  // 头部长度应该>=20，化作headLength就是应该>=5，如果<=4就错了
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
        return 1;
    }
    
    byte timeToLive = buffer[8];
    if (timeToLive == 0) { // 生存时间如果为0，就代表该丢弃
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
        return 1;
    }
    
    // 第二个参数是unsigned short数组的长度，头部共headLength*4个字节，所以有headLength*2个unsigned short
	unsigned short sum = checksum((unsigned short *) buffer, (int) headLength * 2);
    if (sum != 0) {
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
        return 1;
    }

    unsigned int myAddr = getIpv4Address(); // 获得本机IP地址
    unsigned int destAddr = ntohl(((unsigned int*) buffer)[4]); // 分组的目的地址，注意先转换成主机序
    if (destAddr != myAddr && destAddr != 0xffffffff) { // 不是本机地址，也不是广播地址，要丢弃
        ip_DiscardPkt(pBuffer, STUD_IP_TEST_DESTINATION_ERROR);
        return 1;
    }
    
    ip_SendtoUp(pBuffer + headLength * 4, length - headLength * 4); // 上交的时候把头部去掉
    return 0;
}

int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
				   unsigned int dstAddr,byte protocol,byte ttl)
{
    char *buffer = (char *) malloc(len + 20);
    memset(buffer, 0, len + 20);
    memcpy(buffer + 20, pBuffer, len);  // 把除了头部外的内容拷贝过来

    buffer[0] = 0x45;  // 协议号和头部长度
    ((unsigned short*) buffer)[1] = htons(len + 20); // 总长度
    buffer[8] = ttl;
    buffer[9] = protocol;
    ((unsigned int*) buffer)[3] = htonl(srcAddr);
    ((unsigned int*) buffer)[4] = htonl(dstAddr); // 源地址和目的地址都要转成网络序才能发

    unsigned short sum = checksum((unsigned short *) buffer, 10);
    ((unsigned short *) buffer)[5] = htons(sum);

    ip_SendtoLower(buffer, len + 20);
	return 0;
}

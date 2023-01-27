/*
* THIS FILE IS FOR IP FORWARD TEST
*/
#include "sysInclude.h"
#include <vector>

// system support
extern void fwd_LocalRcv(char *pBuffer, int length);

extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);

extern void fwd_DiscardPkt(char *pBuffer, int type);

extern unsigned int getIpv4Address( );

// implemented by students

vector<stud_route_msg *> router;  // 路由表就使用简单的vector，进行线性查找

void stud_Route_Init()  // 初始化无需特定的操作
{
	return;
}

void stud_route_add(stud_route_msg *proute)
{
    stud_route_msg *newProute = (stud_route_msg *) malloc(sizeof(stud_route_msg));
    memcpy(newProute, proute, sizeof(stud_route_msg));  // 这里不直接用proute，而是专门开辟新的内存，拷贝过来
    router.push_back(newProute);  // 加入路由表
	return;
}

unsigned int getMatchLen(unsigned int Xor)  // 计算从最高位开始，共有几个连续的1，代表最长匹配前缀的长度
{
    unsigned int matchLen = 0;
    for (int i = 31; i >= 0; i--)  // 从高位往地位低位循环
    {
        int getbit = (Xor >> i) & 1;
        if (getbit == 1)
            matchLen++;
        else  // 一旦发现某位不是1，就退出，前面连续1的个数就代表匹配上的长度
            break;
    }
    return matchLen;
}

int router_find(unsigned int dest)  // 在路由表中线性查找，找到目的地址dest对应的路由表条目
{
    int nowMax = 0, maxId = -1;  // 分别是当前的最大长度，与其对应的路由表vector下标
    int sz = router.size();
    for (int i = 0; i < sz; i++)
    {
        unsigned int Xor = ~(dest ^ ntohl(router[i]->dest));  // 相同位就变成了1，不同位变成了0
        unsigned int matchLen = getMatchLen(Xor);
        if (matchLen >= ntohl(router[i]->masklen) && matchLen >= nowMax)  // 匹配长度大于masklen且是目前最大的
            nowMax = matchLen, maxId = i;
    }
    return maxId;
}

unsigned short checksum(unsigned short *buffer, int length)  // 计算校验和，与lab2相同
{
    unsigned int sum = 0;
    for (int i = 0; i < length; i++)
    {
        sum += ntohs(buffer[i]);
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return ~(unsigned short) sum;
}

int stud_fwd_deal(char *pBuffer, int length)
{
    char *buffer = (char *) malloc(length);
    memcpy(buffer, pBuffer, length);

    unsigned int myAddr = getIpv4Address();
    unsigned int destAddr = ntohl(((unsigned int*) buffer)[4]);
    if (destAddr == myAddr) {  // 是本机接收的分组，直接接收
        fwd_LocalRcv(pBuffer, length);
        return 0;
    }

    byte timeToLive = buffer[8];
    if (timeToLive == 0) {  // TTL为0就丢弃
        ip_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
        return 1;
    }

    int matched = router_find(destAddr);  // 路由表下标
    if(matched < 0) {  // 找不到路由，丢弃
        fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_NOROUTE);
        return 1;
    }
    stud_route_msg *ans = router[matched];

    buffer[8] -= 1;  // TTL-1
    ((unsigned short *) buffer)[5] = 0;
    unsigned short headLength = buffer[0] & (0xf);
    unsigned short sum = checksum((unsigned short *) buffer, headLength * 2);  // 重新计算校验和
    ((unsigned short *) buffer)[5] = htons(sum);

    fwd_SendtoLower(buffer, length, ans->nexthop);  // 第三个参数是下一跳的地址
	return 0;
}

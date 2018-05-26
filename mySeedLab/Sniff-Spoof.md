## Packet Sniffing and Spoofing

- 什么是报文嗅探sniffing?

- 什么是报文伪造spoofing?

- sniffing-理解sniffex
sniffex嗅探原理:
`dev = pcap_lookupdev` 寻找捕获设备/网卡
`pcap_lookupnet` 获取网卡的IP和掩码
`handle = pcap_open_live` 打开抓包的设备/网卡
`pcap_datalink` 判断是否是以太网
`pcap_compile` 编译过滤条件
`pcap_setfilter` 应用过滤条件
`pcap_loop` 循环抓包
`got_packet` 回调函数处理报文
注意:
需要应用在`root`特权下

如果没在特权下将会报错!
```
gu@ubuntu:~/Code$ gcc mysniff.c -lpcap
gu@ubuntu:~/Code$ ls
a.out  mysniff.c
gu@ubuntu:~/Code$ ./a.out
The sniff interface is:ens33
ERROR:ens33: You don't have permission to capture on that device (socket: Operation not permitted)
gu@ubuntu:~/Code$

```

- sniffing-编写过滤器程序
这是我研一时候写的代码 发表在博客园 已经过去整整24个月了 **青涩**!
在这里稍微修改了一下!

```
#include<stdio.h>
#include<pcap.h>
#include<unistd.h>
#include<stdlib.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ether.h>
#include<arpa/inet.h>
#define ETHER_SIZE 14

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

///get_packet()回调函数
///header:收到的数据包的pcap_pkthdr类型的指针
///packet:收到的数据包数据
void get_packet(u_char*args, const struct pcap_pkthdr *header,const u_char *packet){
     
    static int count = 1;
    const char * payload;
    printf("==================================packet number: %d=============================\n",count++);
     
    ///ETHER_SIZE：以太帧首部长度14个字节
    ///IP包头(tcp包头(数据))
    ///IP包头(udp包头(数据))
    ///IP包头(icmp包头(数据))
    struct ip * ip = (struct ip *)(packet + ETHER_SIZE);
    printf("IP header length: %d\n",ip->ip_hl<<2);
    printf("From %s\n",inet_ntoa(ip->ip_src));
    printf("To %s\n",inet_ntoa(ip->ip_dst));
    int ip_hl = ip->ip_hl<<2;
 
    ///对报文类型进行了扩展
    ///可以分析IP包、ICMP包、TCP包、UDP包
    switch(ip->ip_p){
 
        case IPPROTO_TCP:
        {
            printf("----Protocol TCP----\n");
            struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_hl);           
            printf("tcp -> source:%d\n",ntohs(tcp -> source));
            printf("tcp -> dest:%d\n",ntohs(tcp -> dest));
            printf("tcp -> seq:%d\n",ntohs(tcp -> seq));
            printf("tcp -> ack_seq:%d\n",ntohs(tcp -> ack_seq));     
            printf("tcp -> headerLenth:%d\n",tcp -> doff << 2);
            printf("tcp -> fin:%d\n",tcp -> fin);
            printf("tcp -> syn:%d\n",tcp -> syn);
            printf("tcp -> rst:%d\n",tcp -> rst);
            printf("tcp -> psh:%d\n",tcp -> psh);
            printf("tcp -> ack:%d\n",tcp -> ack);
            printf("tcp -> urg:%d\n",tcp -> urg);
            printf("tcp -> window:%d\n",ntohs(tcp -> window));
            printf("tcp -> check:%d\n",ntohs(tcp -> check)); 
             
            int h_size = tcp->doff<< 2;
            int payload_size = ntohs(ip->ip_len) - ip_hl - h_size;
             
            int i = payload_size;
            printf("payload is:%d\n",i);
            print_payload((char*)tcp + h_size,payload_size);

            break;
        }
        case IPPROTO_UDP:
        {
            printf("----Protocol UDP----\n");
            struct udphdr *udp = (struct udphdr *)(packet + 14 + ip_hl);           
            printf("udp -> source:%d\n",ntohs(udp -> source));
            printf("udp -> dest:%d\n",ntohs(udp -> dest));
            printf("udp -> length:%d\n",ntohs(udp -> len));
            printf("udp -> check:%d\n",ntohs(udp -> check));
            int payload_size = ntohs(ip->ip_len) - ip_hl - 8;
            int i = payload_size;
            printf("payload is:%d\n",i);
            print_payload((char*)udp +8,payload_size);

            break;
        }
        case IPPROTO_ICMP:
        {
            printf("----Protocol ICMP----\n");
            struct icmphdr *icmp = (struct icmphdr *)(packet + 14 + ip_hl);
 
            if(icmp -> type == 8)
            {
                printf("--icmp_echo request--\n");
                printf("icmp -> type:%d\n",icmp -> type);
                printf("icmp -> code:%d\n",icmp -> code);
                printf("icmp -> checksum:%d\n",icmp -> checksum);
     
                printf("icmp -> id:%d\n",icmp -> un.echo.id);
                printf("icmp -> sequence:%d\n",icmp -> un.echo.sequence);
                int payload_size = ntohs(ip->ip_len) - ip_hl - 8;
                int i = payload_size;
                printf("payload is:%d\n",i);
                print_payload((char*)ip + ip_hl +8,payload_size);
             

            }
            else if(icmp -> type == 0)
            {
                printf("--icmp_echo reply--\n");
                printf("icmp -> type:%d\n",icmp -> type);
                printf("icmp -> code:%d\n",icmp -> code);
                printf("icmp -> checksum:%d\n",icmp -> checksum);            
 
                printf("icmp -> id:%d\n",icmp -> un.echo.id);
                printf("icmp -> sequence:%d\n",icmp -> un.echo.sequence);
                int payload_size = ntohs(ip->ip_len) - ip_hl - 8;
                int i = payload_size;
                printf("payload is:%d\n",i);
                print_payload((char*)ip + ip_hl +8,payload_size);

            }
            else
            {
                printf("icmp -> type:%d\n",icmp -> type);
                printf("icmp -> code:%d\n",icmp -> code);
                printf("icmp -> checksum:%d\n",icmp -> checksum);
                int payload_size = ntohs(ip->ip_len) - ip_hl - 8;
                int i = payload_size;
                printf("payload is:%d\n",i);
                print_payload((char*)ip + ip_hl +8,payload_size);
            }
            break;     
        }
        case IPPROTO_IP:
        {
            printf("----Protocol IP----\n");
            //printf("IP header length: %d\n",ip -> ip_hl<<2);
            printf("IP version: %d\n",ip -> ip_v);
            printf("IP type of service: %d\n",ip -> ip_tos);
            printf("IP total length: %d\n",ip -> ip_len);
            printf("IP identification: %d\n",ip -> ip_id);
            printf("IP fragment offset field: %d\n",ip -> ip_off);
            printf("IP time to live: %d\n",ip -> ip_ttl);
            printf("IP protocol: %d\n",ip -> ip_p);
            printf("IP checksum: %d\n",ip -> ip_sum);
            int payload_size = ntohs(ip->ip_len) - ip_hl;
            int i = payload_size;
            printf("payload is:%d\n",i);           
            print_payload((char*)ip + ip_hl,payload_size);
            break;         
        }          
        default:printf("Protocol unknown\n");
        return;
    }
}
          
int main(int argc,char*argv[]){
 
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;  
    int num_packets = 10;
     
    ///pcap_lookupdev()自动获取网络接口，返回一个网络接口的字符串指针
    ///如果出错，errbuf存放出错信息
    ///若想手动指定，则跳过此步，将要监听的网络字符串硬编码到pcap_open_live中
    dev = pcap_lookupdev(errbuf);
    if(dev==NULL){
        printf("ERROR:%s\n",errbuf);
        exit(2);
    }
    printf("The sniff interface is:%s\n",dev);
 
    ///pcap_lookupnet()获得设备的IP地址，子网掩码等信息
    ///net：网络接口的IP地址
    ///mask：网络接口的子网掩码
    if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1){
        printf("ERROR:%s\n",errbuf);
        net = 0;
        mask = 0;
    }  
 
    ///pcap_open_live()打开网络接口
    ///BUFSIZ:抓包长度
    ///第三个参数：0代表非混杂模式，1代表混杂模式
    ///第四个参数：等待的毫秒数，超过这个值，获取数据包的函数会立即返回，0表示一直等待直到有数据包到来
    pcap_t * handle = pcap_open_live(dev,BUFSIZ,1,0,errbuf);
    if(handle == NULL){
        printf("ERROR:%s\n",errbuf);
        exit(2);
    }
    ///pcap_compile()编译过滤表达式
    ///fp指向编译后的filter_exp
    ///filter_exp过滤表达式
    ///参数四：是否需要优化过滤表达式
    if(pcap_compile(handle,&fp,filter_exp,0,net)==-1){
        printf("Can't parse filter %s:%s\n",filter_exp,pcap_geterr(handle));
        return(2);
    }
     
    ///pcap_setfilter()应用这个过滤表达式
    ///完成过滤表达式后，我们可以使用pcap_loop()或pcap_next()登抓包函数抓包了
    if(pcap_setfilter(handle,&fp)==-1){
        printf("cant' install filter %s:%s\n",filter_exp,pcap_geterr(handle));
        return(2);
    }  
    printf("Hello hacker! i am ailx10.welcome to http://hackbiji.top\n"); 
 
//  packet = pcap_next(handle,&header);
//  printf("Get a packet with length %d.\n",header.len);
 
    ///
    ///num_packets:需要抓的数据包的个数，一旦抓到了num_packets个数据包，pcap_loop立即返回。负数表示永远循环抓包，直到出错
    ///get_packet：回调函数指针
    //pcap_loop(handle,num_packets,get_packet,NULL);
    pcap_loop(handle,-1,get_packet,NULL);
     
    pcap_freecode(&fp);
     
    ///pcap_close()释放网络接口
    ///关闭pcap_open_live()获取的pcap_t的网络接口对象并释放相关资源
    pcap_close(handle);
    return(0);
}
```

我们ping一下`黑客笔记`网站 `ping hackbiji.top`
```
gu@ubuntu:~/Code$ ping hackbiji.top
PING hackbiji.top (192.30.252.153) 56(84) bytes of data.
64 bytes from 192.30.252.153: icmp_seq=1 ttl=128 time=262 ms
64 bytes from 192.30.252.153: icmp_seq=2 ttl=128 time=275 ms
```
程序运行结果:

![sniff_icmp](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/Sniff-Spoof/sniff_icmp.png)

- sniffing-嗅探telnet密码
稍微修改一下代码 方便我们控制过滤条件
1.监听`dst port 23`
2.编译运行`sudo ./a.out "dst port 23"`
3.在虚拟机中开启telnet`sudo service openbsd-inetd start `
4.在主机上访问虚拟机`telnet 192.168.59.146`
结果如图所示:
其中用户名和密码都为`gu`!!
![sniff_telnet](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/Sniff-Spoof/sniff_telnet.png)

```c
#include<stdio.h>
#include<pcap.h>
#include<unistd.h>
#include<stdlib.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ether.h>
#include<arpa/inet.h>
#define ETHER_SIZE 14
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
} 
///get_packet()回调函数
///header:收到的数据包的pcap_pkthdr类型的指针
///packet:收到的数据包数据
void get_packet(u_char*args, const struct pcap_pkthdr *header,const u_char *packet){
     
    static int count = 1;
    const char * payload;
    //printf("==================================packet number: %d=============================\n",count++);
    
    struct ip * ip = (struct ip *)(packet + ETHER_SIZE);
    //printf("IP header length: %d\n",ip->ip_hl<<2);
    //printf("From %s\n",inet_ntoa(ip->ip_src));
    //printf("To %s\n",inet_ntoa(ip->ip_dst));
    int ip_hl = ip->ip_hl<<2;
 

    switch(ip->ip_p){
 
        case IPPROTO_TCP:
        {
            printf("----Protocol TCP----\n");
            struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_hl);          
            int h_size = tcp->doff<< 2;
            int payload_size = ntohs(ip->ip_len) - ip_hl - h_size;
            int i = payload_size;
            print_payload((char*)tcp + h_size,payload_size);

            break;
        }
                  
        default:
            break;
        return;
    }
}
         
 
 
int main(int argc,char*argv[]){
 
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char *filter_exp = argv[1];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;  
    int num_packets = 10;
     
    ///pcap_lookupdev()自动获取网络接口，返回一个网络接口的字符串指针
    ///如果出错，errbuf存放出错信息
    ///若想手动指定，则跳过此步，将要监听的网络字符串硬编码到pcap_open_live中
    dev = pcap_lookupdev(errbuf);
    if(dev==NULL){
        printf("ERROR:%s\n",errbuf);
        exit(2);
    }
    printf("The sniff interface is:%s\n",dev);
 
    ///pcap_lookupnet()获得设备的IP地址，子网掩码等信息
    ///net：网络接口的IP地址
    ///mask：网络接口的子网掩码
    if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1){
        printf("ERROR:%s\n",errbuf);
        net = 0;
        mask = 0;
    }  
 
    ///pcap_open_live()打开网络接口
    ///BUFSIZ:抓包长度
    ///第三个参数：0代表非混杂模式，1代表混杂模式
    ///第四个参数：等待的毫秒数，超过这个值，获取数据包的函数会立即返回，0表示一直等待直到有数据包到来
    pcap_t * handle = pcap_open_live(dev,BUFSIZ,1,0,errbuf);
    if(handle == NULL){
        printf("ERROR:%s\n",errbuf);
        exit(2);
    }
    ///pcap_compile()编译过滤表达式
    ///fp指向编译后的filter_exp
    ///filter_exp过滤表达式
    ///参数四：是否需要优化过滤表达式
    if(pcap_compile(handle,&fp,filter_exp,0,net)==-1){
        printf("Can't parse filter %s:%s\n",filter_exp,pcap_geterr(handle));
        return(2);
    }
     
    ///pcap_setfilter()应用这个过滤表达式
    ///完成过滤表达式后，我们可以使用pcap_loop()或pcap_next()登抓包函数抓包了
    if(pcap_setfilter(handle,&fp)==-1){
        printf("cant' install filter %s:%s\n",filter_exp,pcap_geterr(handle));
        return(2);
    }  
    printf("Hello hacker! i am ailx10.welcome to http://hackbiji.top\n"); 
 
//  packet = pcap_next(handle,&header);
//  printf("Get a packet with length %d.\n",header.len);
 
    ///
    ///num_packets:需要抓的数据包的个数，一旦抓到了num_packets个数据包，pcap_loop立即返回。负数表示永远循环抓包，直到出错
    ///get_packet：回调函数指针
    //pcap_loop(handle,num_packets,get_packet,NULL);
    pcap_loop(handle,-1,get_packet,NULL);
     
    pcap_freecode(&fp);
     
    ///pcap_close()释放网络接口
    ///关闭pcap_open_live()获取的pcap_t的网络接口对象并释放相关资源
    pcap_close(handle);
    return(0);
}
```

- spoofing-伪造IP
抓包:
![spoof_tcp](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/Sniff-Spoof/spoof_tcp.png)

程序源码分析:

```c
/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)
保留注释 这里我们为了学习原理 稍微修改源码
修改1:接口改为自己的wlan0
修改2:源IP地址 改为自己的IP地址
修改3:目的网址 改为自己期待的网址
*/

// Send an IPv4 TCP packet via raw socket.
// Stack fills out layer 2 (data link) information (MAC addresses) for us.
// Values set for SYN packet, no TCP options data.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_TCP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#define __FAVOR_BSD           // Use BSD format of tcp header
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq

#include <errno.h>            // errno, perror()

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data

// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t tcp4_checksum (struct ip, struct tcphdr);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

int
main (int argc, char **argv)
{
  int i, status, sd, *ip_flags, *tcp_flags;
  const int on = 1;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct tcphdr tcphdr;
  uint8_t *packet;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4, sin;
  struct ifreq ifr;
  void *tmp;

  // Allocate memory for various arrays.
  packet = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);
  tcp_flags = allocate_intmem (8);

  // Interface to send packet through.
  strcpy (interface, "wlan0");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface index which we will use to
  // bind socket descriptor sd to specified interface with setsockopt() since
  // none of the other arguments of sendto() specify which interface to use.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
    perror ("ioctl() failed to find interface ");
    return (EXIT_FAILURE);
  }
  close (sd);
  printf ("Index for interface %s is %i\n", interface, ifr.ifr_ifindex);

  // Source IPv4 address: you need to fill this out
  strcpy (src_ip, "192.168.0.101");

  // Destination URL or IPv4 address: you need to fill this out
  strcpy (target, "hackbiji.top");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + TCP header
  iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN);

  // ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 6 for TCP
  iphdr.ip_p = IPPROTO_TCP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

  // TCP header

  // Source port number (16 bits)
  tcphdr.th_sport = htons (60);

  // Destination port number (16 bits)
  tcphdr.th_dport = htons (80);

  // Sequence number (32 bits)
  tcphdr.th_seq = htonl (0);

  // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
  tcphdr.th_ack = htonl (0);

  // Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): size of TCP header in 32-bit words
  tcphdr.th_off = TCP_HDRLEN / 4;

  // Flags (8 bits)

  // FIN flag (1 bit)
  tcp_flags[0] = 0;

  // SYN flag (1 bit): set to 1
  tcp_flags[1] = 1;

  // RST flag (1 bit)
  tcp_flags[2] = 0;

  // PSH flag (1 bit)
  tcp_flags[3] = 0;

  // ACK flag (1 bit)
  tcp_flags[4] = 0;

  // URG flag (1 bit)
  tcp_flags[5] = 0;

  // ECE flag (1 bit)
  tcp_flags[6] = 0;

  // CWR flag (1 bit)
  tcp_flags[7] = 0;

  tcphdr.th_flags = 0;
  for (i=0; i<8; i++) {
    tcphdr.th_flags += (tcp_flags[i] << i);
  }

  // Window size (16 bits)
  tcphdr.th_win = htons (65535);

  // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr.th_urp = htons (0);

  // TCP checksum (16 bits)
  tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr);

  // Prepare packet.

  // First part is an IPv4 header.
  memcpy (packet, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

  // Next part of packet is upper layer protocol header.
  memcpy ((packet + IP4_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

  // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
  // For that, we need to specify a destination for the kernel in order for it
  // to decide where to send the raw datagram. We fill in a struct in_addr with
  // the desired destination IP address, and pass this structure to the sendto() function.
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

  // Submit request for a raw socket descriptor.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
    perror ("setsockopt() failed to set IP_HDRINCL ");
    exit (EXIT_FAILURE);
  }

  // Bind socket to interface index.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    perror ("setsockopt() failed to bind to interface ");
    exit (EXIT_FAILURE);
  }

  // Send packet.
  if (sendto (sd, packet, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    perror ("sendto() failed ");
    exit (EXIT_FAILURE);
  }

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (packet);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (ip_flags);
  free (tcp_flags);

  return (EXIT_SUCCESS);
}

// Computing the internet checksum (RFC 1071).
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr)
{
  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  // ptr points to beginning of buffer buf
  ptr = &buf[0];

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy TCP length to buf (16 bits)
  svalue = htons (sizeof (tcphdr));
  memcpy (ptr, &svalue, sizeof (svalue));
  ptr += sizeof (svalue);
  chksumlen += sizeof (svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  return checksum ((uint16_t *) buf, chksumlen);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}
```
- spoofing-伪造ICMP
抓包:
![spoof_icmp4](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/Sniff-Spoof/spoof_icmp4.png)


程序源码分析:
```c
/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)
保留注释 这里我们为了学习原理 稍微修改源码
修改1:接口改为自己的wlan0
修改2:源IP地址 改为自己的IP地址
修改3:目的网址 改为自己期待的网址
*/
// Send an IPv4 ICMP packet via raw socket.
// Stack fills out layer 2 (data link) information (MAC addresses) for us.
// Values set for echo request packet, includes some ICMP data.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq

#include <errno.h>            // errno, perror()

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data

// Function prototypes
uint16_t checksum (uint16_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

int
main (int argc, char **argv)
{
  int status, datalen, sd, *ip_flags;
  const int on = 1;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct icmp icmphdr;
  uint8_t *data, *packet;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4, sin;
  struct ifreq ifr;
  void *tmp;

  // Allocate memory for various arrays.
  data = allocate_ustrmem (IP_MAXPACKET);
  packet = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);

  // Interface to send packet through.
  strcpy (interface, "wlan0");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface index which we will use to
  // bind socket descriptor sd to specified interface with setsockopt() since
  // none of the other arguments of sendto() specify which interface to use.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
    perror ("ioctl() failed to find interface ");
    return (EXIT_FAILURE);
  }
  close (sd);
  printf ("Index for interface %s is %i\n", interface, ifr.ifr_ifindex);

  // Source IPv4 address: you need to fill this out
  strcpy (src_ip, "192.168.0.101");

  // Destination URL or IPv4 address: you need to fill this out
  strcpy (target, "hackbiji.top");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // ICMP data
  datalen = 4;
  data[0] = 'H';
  data[1] = 'a';
  data[2] = 'c';
  data[3] = 'k';

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 1 for ICMP
  iphdr.ip_p = IPPROTO_ICMP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

  // ICMP header

  // Message Type (8 bits): echo request
  icmphdr.icmp_type = ICMP_ECHO;

  // Message Code (8 bits): echo request
  icmphdr.icmp_code = 0;

  // Identifier (16 bits): usually pid of sending process - pick a number
  icmphdr.icmp_id = htons (1000);

  // Sequence Number (16 bits): starts at 0
  icmphdr.icmp_seq = htons (0);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  icmphdr.icmp_cksum = 0;

  // Prepare packet.

  // First part is an IPv4 header.
  memcpy (packet, &iphdr, IP4_HDRLEN);

  // Next part of packet is upper layer protocol header.
  memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

  // Finally, add the ICMP data.
  memcpy (packet + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

  // Calculate ICMP header checksum
  icmphdr.icmp_cksum = checksum ((uint16_t *) (packet + IP4_HDRLEN), ICMP_HDRLEN + datalen);
  memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

  // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
  // For that, we need to specify a destination for the kernel in order for it
  // to decide where to send the raw datagram. We fill in a struct in_addr with
  // the desired destination IP address, and pass this structure to the sendto() function.
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

  // Submit request for a raw socket descriptor.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
    perror ("setsockopt() failed to set IP_HDRINCL ");
    exit (EXIT_FAILURE);
  }

  // Bind socket to interface index.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    perror ("setsockopt() failed to bind to interface ");
    exit (EXIT_FAILURE);
  }

  // Send packet.
  if (sendto (sd, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    perror ("sendto() failed ");
    exit (EXIT_FAILURE);
  }

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (data);
  free (packet);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (ip_flags);

  return (EXIT_SUCCESS);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}
```
- spoofing-伪造MAC
抓包:
![spoof_myping](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/Sniff-Spoof/spoof_myping.png)
程序运行结果:
```
root@gt:~/Desktop# gcc ping4_ll.c -o ping4_ll
root@gt:~/Desktop# ./ping4_ll 
MAC address for interface wlan0 is 18:65:90:cb:f0:5d
Index for interface wlan0 is 7
192.30.252.153  304.613 ms (46 bytes received)
```
程序源码分析:
```c
/*  Copyright (C) 2011-2015  P.D. Buchan (pdbuchan@yahoo.com)
保留注释 这里我们为了学习原理 稍微修改源码
修改1:接口改为自己的wlan0
修改2:目的MAC地址 可以自己先ping一下目标主机 wireshark抓包获取
修改3:源IP地址 改为自己的IP地址
修改4:目的网址 改为自己期待的网址
*/

// Send an IPv4 ICMP echo request packet via raw socket at the link layer (ethernet frame),
// and receive echo reply packet (i.e., ping). Includes some ICMP data.
// Need to have destination MAC address.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <sys/time.h>         // gettimeofday()

#include <errno.h>            // errno, perror()

// Define some constants.
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data

// Function prototypes
uint16_t checksum (uint16_t *, int);
uint16_t icmp4_checksum (struct icmp, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

int
main (int argc, char **argv)
{
  int i, status, datalen, frame_length, sendsd, recvsd, bytes, *ip_flags, timeout, trycount, trylim, done;
  char *interface, *target, *src_ip, *dst_ip, *rec_ip;
  struct ip send_iphdr, *recv_iphdr;
  struct icmp send_icmphdr, *recv_icmphdr;
  uint8_t *data, *src_mac, *dst_mac, *send_ether_frame, *recv_ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  struct sockaddr from;
  socklen_t fromlen;
  struct timeval wait, t1, t2;
  struct timezone tz;
  double dt;
  void *tmp;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  send_ether_frame = allocate_ustrmem (IP_MAXPACKET);
  recv_ether_frame = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  rec_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);

  // Interface to send packet through.
  strcpy (interface, "wlan0");

  // Submit request for a socket descriptor to look up interface.
  // We'll use it to send packets as well, so we leave it open.
  if ((sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sendsd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }

  // Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);

  // Report source MAC address to stdout.
  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

  // Set destination MAC address: you need to fill these out
  dst_mac[0] = 0x94;
  dst_mac[1] = 0xd9;
  dst_mac[2] = 0xb3;
  dst_mac[3] = 0x66;
  dst_mac[4] = 0xef;
  dst_mac[5] = 0x5c;

  // Source IPv4 address: you need to fill this out
  strcpy (src_ip, "192.168.0.101");

  // Destination URL or IPv4 address: you need to fill this out
  strcpy (target, "hackbiji.top");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6);
  device.sll_halen = 6;

  // ICMP data
  datalen = 4;
  data[0] = 'H';
  data[1] = 'a';
  data[2] = 'c';
  data[3] = 'k';

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  send_iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  send_iphdr.ip_v = 4;

  // Type of service (8 bits)
  send_iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  send_iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  send_iphdr.ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  send_iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  send_iphdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 1 for ICMP
  send_iphdr.ip_p = IPPROTO_ICMP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(send_iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(send_iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  send_iphdr.ip_sum = 0;
  send_iphdr.ip_sum = checksum ((uint16_t *) &send_iphdr, IP4_HDRLEN);

  // ICMP header

  // Message Type (8 bits): echo request
  send_icmphdr.icmp_type = ICMP_ECHO;

  // Message Code (8 bits): echo request
  send_icmphdr.icmp_code = 0;

  // Identifier (16 bits): usually pid of sending process - pick a number
  send_icmphdr.icmp_id = htons (1000);

  // Sequence Number (16 bits): starts at 0
  send_icmphdr.icmp_seq = htons (0);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  send_icmphdr.icmp_cksum = icmp4_checksum (send_icmphdr, data, datalen);

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
  frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + datalen;

  // Destination and Source MAC addresses
  memcpy (send_ether_frame, dst_mac, 6);
  memcpy (send_ether_frame + 6, src_mac, 6);

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  send_ether_frame[12] = ETH_P_IP / 256;
  send_ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

  // IPv4 header
  memcpy (send_ether_frame + ETH_HDRLEN, &send_iphdr, IP4_HDRLEN);

  // ICMP header
  memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &send_icmphdr, ICMP_HDRLEN);

  // ICMP data
  memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

  // Submit request for a raw socket descriptor to receive packets.
  if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to obtain a receive socket descriptor ");
    exit (EXIT_FAILURE);
  }

  // Set maximum number of tries to ping remote host before giving up.
  trylim = 3;
  trycount = 0;

  // Cast recv_iphdr as pointer to IPv4 header within received ethernet frame.
  recv_iphdr = (struct ip *) (recv_ether_frame + ETH_HDRLEN);

  // Cast recv_icmphdr as pointer to ICMP header within received ethernet frame.
  recv_icmphdr = (struct icmp *) (recv_ether_frame + ETH_HDRLEN + IP4_HDRLEN);

  done = 0;
  for (;;) {

    // SEND

    // Send ethernet frame to socket.
    if ((bytes = sendto (sendsd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
      perror ("sendto() failed ");
      exit (EXIT_FAILURE);
    }

    // Start timer.
    (void) gettimeofday (&t1, &tz);

    // Set time for the socket to timeout and give up waiting for a reply.
    timeout = 2;
    wait.tv_sec  = timeout; 
    wait.tv_usec = 0;
    setsockopt (recvsd, SOL_SOCKET, SO_RCVTIMEO, (char *) &wait, sizeof (struct timeval));

    // Listen for incoming ethernet frame from socket recvsd.
    // We expect an ICMP ethernet frame of the form:
    //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
    //     + ethernet data (IPv4 header + ICMP header)
    // Keep at it for 'timeout' seconds, or until we get an ICMP reply.

    // RECEIVE LOOP
    for (;;) {

      memset (recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
      memset (&from, 0, sizeof (from));
      fromlen = sizeof (from);
      if ((bytes = recvfrom (recvsd, recv_ether_frame, IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen)) < 0) {

        status = errno;

        // Deal with error conditions first.
        if (status == EAGAIN) {  // EAGAIN = 11
          printf ("No reply within %i seconds.\n", timeout);
          trycount++;
          break;  // Break out of Receive loop.
        } else if (status == EINTR) {  // EINTR = 4
          continue;  // Something weird happened, but let's keep listening.
        } else {
          perror ("recvfrom() failed ");
          exit (EXIT_FAILURE);
        }
      }  // End of error handling conditionals.

      // Check for an IP ethernet frame, carrying ICMP echo reply. If not, ignore and keep listening.
      if ((((recv_ether_frame[12] << 8) + recv_ether_frame[13]) == ETH_P_IP) &&
         (recv_iphdr->ip_p == IPPROTO_ICMP) && (recv_icmphdr->icmp_type == ICMP_ECHOREPLY) && (recv_icmphdr->icmp_code == 0)) {

        // Stop timer and calculate how long it took to get a reply.
        (void) gettimeofday (&t2, &tz);
        dt = (double) (t2.tv_sec - t1.tv_sec) * 1000.0 + (double) (t2.tv_usec - t1.tv_usec) / 1000.0;

        // Extract source IP address from received ethernet frame.
        if (inet_ntop (AF_INET, &(recv_iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL) {
          status = errno;
          fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
          exit (EXIT_FAILURE);
        }

        // Report source IPv4 address and time for reply.
        printf ("%s  %g ms (%i bytes received)\n", rec_ip, dt, bytes);
        done = 1;
        break;  // Break out of Receive loop.
      }  // End if IP ethernet frame carrying ICMP_ECHOREPLY
    }  // End of Receive loop.

    // The 'done' flag was set because an echo reply was received; break out of send loop.
    if (done == 1) {
      break;  // Break out of Send loop.
    }

    // We ran out of tries, so let's give up.
    if (trycount == trylim) {
      printf ("Recognized no echo replies from remote host after %i tries.\n", trylim);
      break;
    }

  }  // End of Send loop.

  // Close socket descriptors.
  close (sendsd);
  close (recvsd);

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (data);
  free (send_ether_frame);
  free (recv_ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (rec_ip);
  free (ip_flags);

  return (EXIT_SUCCESS);
}

// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t
icmp4_checksum (struct icmp icmphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy Message Type to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_type, sizeof (icmphdr.icmp_type));
  ptr += sizeof (icmphdr.icmp_type);
  chksumlen += sizeof (icmphdr.icmp_type);

  // Copy Message Code to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_code, sizeof (icmphdr.icmp_code));
  ptr += sizeof (icmphdr.icmp_code);
  chksumlen += sizeof (icmphdr.icmp_code);

  // Copy ICMP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy Identifier to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_id, sizeof (icmphdr.icmp_id));
  ptr += sizeof (icmphdr.icmp_id);
  chksumlen += sizeof (icmphdr.icmp_id);

  // Copy Sequence Number to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_seq, sizeof (icmphdr.icmp_seq));
  ptr += sizeof (icmphdr.icmp_seq);
  chksumlen += sizeof (icmphdr.icmp_seq);

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}
```
- 通过ping命名看网络欺骗的本质
![sniff_spoof](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/Sniff-Spoof/sniff_spoof.png)

稍微修改一下sniff和spoof的代码
```
#include<stdio.h>
#include<pcap.h>
#include<unistd.h>
#include<stdlib.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ether.h>
#include<arpa/inet.h>
#include <string.h>           // strcpy, memset(), and memcpy()
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP, INET_ADDRSTRLEN
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <errno.h>            // errno, perror()
#define ETHER_SIZE 14
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
uint16_t checksum (uint16_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

int sendICMPReplyto(char* dev,char* ip_src,char* ip_dst)
{
int status, datalen, sd, *ip_flags;
  const int on = 1;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct icmp icmphdr;
  uint8_t *data, *packet;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4, sin;
  struct ifreq ifr;
  void *tmp;

  // Allocate memory for various arrays.
  data = allocate_ustrmem (IP_MAXPACKET);
  packet = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);

  // Interface to send packet through.
  strcpy (interface, dev);

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface index which we will use to
  // bind socket descriptor sd to specified interface with setsockopt() since
  // none of the other arguments of sendto() specify which interface to use.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0) {
    perror ("ioctl() failed to find interface ");
    return (EXIT_FAILURE);
  }
  close (sd);
  //printf ("Index for interface %s is %i\n", interface, ifr.ifr_ifindex);

  // Source IPv4 address: you need to fill this out
  strcpy (src_ip, ip_src);

  // Destination URL or IPv4 address: you need to fill this out
  strcpy (target, ip_dst);

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // ICMP data
  datalen = 4;
  data[0] = 'H';
  data[1] = 'a';
  data[2] = 'c';
  data[3] = 'k';

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 1 for ICMP
  iphdr.ip_p = IPPROTO_ICMP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

  // ICMP header

  // Message Type (8 bits): echo reply
  icmphdr.icmp_type = ICMP_ECHOREPLY;

  // Message Code (8 bits): echo request/reply
  icmphdr.icmp_code = 0;

  // Identifier (16 bits): usually pid of sending process - pick a number
  icmphdr.icmp_id = htons (1000);

  // Sequence Number (16 bits): starts at 0
  icmphdr.icmp_seq = htons (0);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  icmphdr.icmp_cksum = 0;

  // Prepare packet.

  // First part is an IPv4 header.
  memcpy (packet, &iphdr, IP4_HDRLEN);

  // Next part of packet is upper layer protocol header.
  memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

  // Finally, add the ICMP data.
  memcpy (packet + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

  // Calculate ICMP header checksum
  icmphdr.icmp_cksum = checksum ((uint16_t *) (packet + IP4_HDRLEN), ICMP_HDRLEN + datalen);
  memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

  // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
  // For that, we need to specify a destination for the kernel in order for it
  // to decide where to send the raw datagram. We fill in a struct in_addr with
  // the desired destination IP address, and pass this structure to the sendto() function.
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

  // Submit request for a raw socket descriptor.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
    perror ("setsockopt() failed to set IP_HDRINCL ");
    exit (EXIT_FAILURE);
  }

  // Bind socket to interface index.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    perror ("setsockopt() failed to bind to interface ");
    exit (EXIT_FAILURE);
  }

  // Send packet.
  if (sendto (sd, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    perror ("sendto() failed ");
    exit (EXIT_FAILURE);
  }

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (data);
  free (packet);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (ip_flags);

  return (EXIT_SUCCESS);
}

void get_packet(u_char* dev, const struct pcap_pkthdr *header,const u_char *packet){
     
    static int count = 1;
    const char * payload;
 
    struct ip * ip = (struct ip *)(packet + ETHER_SIZE);

    int ip_hl = ip->ip_hl<<2;
 
    switch(ip->ip_p){

        case IPPROTO_ICMP:
        {
            struct icmphdr *icmp = (struct icmphdr *)(packet + 14 + ip_hl);
 
            if(icmp -> type == 0 )
            {
                printf("--icmp_echo reply--\n");
                printf("icmp -> type:%d\n",icmp -> type);
                printf("icmp -> code:%d\n",icmp -> code);
                printf("icmp -> checksum:%d\n",icmp -> checksum);
     
                printf("icmp -> id:%d\n",icmp -> un.echo.id);
                printf("icmp -> sequence:%d\n",icmp -> un.echo.sequence);
                int payload_size = ntohs(ip->ip_len) - ip_hl - 8;
                int i = payload_size;
                printf("payload is:%d\n",i);
                print_payload((char*)ip + ip_hl +8,payload_size);
                printf("\n\n");
            }
            else if(icmp -> type == 8 )
            {
                printf("--icmp_echo request--\n");
                printf("icmp -> type:%d\n",icmp -> type);
                printf("icmp -> code:%d\n",icmp -> code);
                printf("icmp -> checksum:%d\n",icmp -> checksum);
     
                printf("icmp -> id:%d\n",icmp -> un.echo.id);
                printf("icmp -> sequence:%d\n",icmp -> un.echo.sequence);
                int payload_size = ntohs(ip->ip_len) - ip_hl - 8;
                int i = payload_size;
                printf("payload is:%d\n",i);
             	print_payload((char*)ip + ip_hl +8,payload_size);

                printf("\n\n");
                sendICMPReplyto(dev,inet_ntoa(ip->ip_dst),inet_ntoa(ip->ip_src));
            }
            
            break;     
        }
        default:
	    break;
        return;
    }
}
         
 
 
int main(int argc,char*argv[]){
 
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char *filter_exp = argv[1];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;  
    int num_packets = 10;
     
    dev = pcap_lookupdev(errbuf);
    if(dev==NULL){
        printf("ERROR:%s\n",errbuf);
        exit(2);
    }
    printf("The sniff interface is:%s\n",dev);
 
    if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1){
        printf("ERROR:%s\n",errbuf);
        net = 0;
        mask = 0;
    }  
 
    pcap_t * handle = pcap_open_live(dev,BUFSIZ,1,0,errbuf);
    if(handle == NULL){
        printf("ERROR:%s\n",errbuf);
        exit(2);
    }

    if(pcap_compile(handle,&fp,filter_exp,0,net)==-1){
        printf("Can't parse filter %s:%s\n",filter_exp,pcap_geterr(handle));
        return(2);
    }
     

    if(pcap_setfilter(handle,&fp)==-1){
        printf("cant' install filter %s:%s\n",filter_exp,pcap_geterr(handle));
        return(2);
    }  
    printf("Hello hacker! i am ailx10.welcome to http://hackbiji.top\n\n"); 
 

    pcap_loop(handle,-1,get_packet,dev);
     
    pcap_freecode(&fp);
     
    pcap_close(handle);
    return(0);
}
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}
```

## 参考
http://www.pdbuchan.com/rawsock/rawsock.html



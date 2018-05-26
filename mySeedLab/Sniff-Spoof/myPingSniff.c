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

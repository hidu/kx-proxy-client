kx-proxy-client
======

这个是[kx-proxy](https://github.com.hidu/kx-proxy)的本地客户端程序

install
```
go get -u  github.com/hidu/kx-proxy-client
```

run
```
kx-proxy-client -addr=127.0.0.1:8200 -conf=conf.json
```
将在本地 <code>127.0.0.1:8200</code>启动http代理服务。

配置文件
```
{
    "proxy":[
        {"url":"https://you-proxy.com/","weight":1,"secertKey":""}
    ],
    "parent":"",
    "ssl":true,
    "ssl_client_cert" :"",
    "ssl_server_key" :""
}
```

https默认使用中间人，需要将 [证书](res/cert.pem) 导入到浏览器中。

或者自己创建证书，并配置conf.json中的<code>ssl_client_cert</code>,<code>ssl_server_key</code>


ssl keygen
```
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 3650
```


kx-proxy-server
https://github.com.hidu/kx-proxy
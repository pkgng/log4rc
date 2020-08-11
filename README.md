
## log4rc 

log proxy for http and https remote call.

http / https 的通用代理服务，记录详细的请求及返回日志。

主要为了解决系统中调用http请求时需要留存原始日志的场景，基本可以0成本添加所有请求的完整日志。

可以在Release 中直接下载可执行程序部署运行


## help

```
    log4rc -h
    Usage of log4rc:
    -addr string
            host:port of the proxy (default ":50080")
    -dialer-timeout int
            timeout of dailing a connect (default 30)
    -disable-keepalive
            if disable keepalive
    -keepalive-duration int
            time Duration of keepAlive (default 30)
    -log string
            full path of the log file (default "./martian.log")
    -log-sync-duration int
            time Duration of sync log from mem to disk (default 2)
    -sign string
            organization name for MITM certificates And via Header on Request for Loop Dectect (default "reqLib")
    -skip-connect-log
            skip connect log (default true)
    -skip-tls-verify
            skip TLS server verification; insecure
    -v int
            log level
```

## 启动方式

```
    nohup  log4rc  &

    默认代理端口 50080，日志会生成到当前目录的 martain.log 中
```

```
    nohup log4rc -skip-connect-log -addr=:9999  -log=/home/log/all.log  -sign=xxxx  &

    不记录http/s 的连接日志， 指定代理端口9999， 指定log文件， 指定请求签名
```


## 请求demo

```
    curl -x 127.0.0.1:50080 -k -d "abcdefgxxxx"  "https://www.baidu.com"

    请求为 https 时需要客户端工作在insecure模式，正常阿里云或者服务器机房中域名不可能被串改，insecure的通信依然是ssl加密的，所以不用担心安全问题。
    curl 的 insecure 模式参数 为： -k 
```


## 日志格式举例

```
{
    "_id": "e536410602b155f8",
    "startedDateTime": "2020-08-11T04:35:48.285336Z",
    "time": 31,
    "request": {
        "method": "POST",
        "url": "https://www.baidu.com/",
        "httpVersion": "HTTP/1.1",
        "cookies": [
            
        ],
        "headers": [
            {
                "name": "X-Forwarded-Url",
                "value": "https://www.baidu.com/"
            },
            {
                "name": "X-Forwarded-For",
                "value": "127.0.0.1"
            },
            {
                "name": "X-Forwarded-Proto",
                "value": "https"
            },
            {
                "name": "Content-Length",
                "value": "11"
            },
            {
                "name": "Content-Type",
                "value": "application/x-www-form-urlencoded"
            },
            {
                "name": "X-Forwarded-Host",
                "value": "www.baidu.com"
            },
            {
                "name": "Accept",
                "value": "*/*"
            },
            {
                "name": "Host",
                "value": "www.baidu.com"
            },
            {
                "name": "User-Agent",
                "value": "curl/7.54.0"
            },
            {
                "name": "Via",
                "value": "1.1 reqLib-6f12c75dfc97a4e66b8f"
            }
        ],
        "queryString": [
            
        ],
        "postData": {
            "mimeType": "application/x-www-form-urlencoded",
            "params": [
                {
                    "name": "abcdefgxxxx"
                }
            ],
            "text": ""
        },
        "headersSize": -1,
        "bodySize": 11
    },
    "response": {
        "status": 302,
        "statusText": "Found",
        "httpVersion": "HTTP/1.1",
        "cookies": [
            
        ],
        "headers": [
            {
                "name": "Server",
                "value": "bfe/1.0.8.18"
            },
            {
                "name": "Content-Length",
                "value": "17931"
            },
            {
                "name": "Content-Type",
                "value": "text/html"
            },
            {
                "name": "Date",
                "value": "Tue, 11 Aug 2020 04:35:48 GMT"
            },
            {
                "name": "Etag",
                "value": "\"54d97485-460b\""
            }
        ],
        "content": {
            "size": 17931,
            "mimeType": "text/html",
            "text": "这里是response的body经base64后的结果",
            "encoding": "base64"
        },
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": 17931
    },
    "cache": {
        
    },
    "timings": {
        "send": 0,
        "wait": 0,
        "receive": 0
    }
}
```

日志中每对请求为一行json序列化后的文本。

## 阿里云部署整合

软件可以使用阿里云SLB以tcp方式代理，实现多服务负载均衡。

日志文件使用阿里云日志服务收集，日志服务选择json格式自动索引即可。

日志如果需要固化可以将日志服务投递到oss中做备份存储。




## 其他

服务代理部分实现完全使用 [martian](https://github.com/google/martian) 

本项目为代理实现方式，另外转发实现方式请到 [log4ic](https://github.com/pkgng/log4ic)




### 安装方式

##### 一、手动安装

1、使用go env查询go ROOT路径。 （例如：GOROOT="/usr/local/go"） 

2、copy 项目文件到tls库 （cp -r ./*_plugin.go /usr/local/go/src/crypto/tls） 

3、编译


##### 二、工具安装

bash install.sh


### 使用方式

```
    conn, err := (&net.Dialer{Timeout: time.Second * 5}).Dial("tcp", addr)
    if err != nil {
        panic(err)
    }

    tlsConf := &tls.Config{
        InsecureSkipVerify: true,
        Certificates:       []tls.Certificate{tls.Certificate{Certificate: [][]byte{[]byte(identity), []byte(psk)}}},
    }

    tc := tls.Client(conn, tlsConf)
    err = tc.HandshakeWithPsk()
    if err != nil {
        panic(err)
    }

    buf := make([]byte, 256)
    tc.Write([]byte("Hello Wolrld"))
    n, _ := tc.Read(buf)
    fmt.Printf(string(buf[:n]))
```


### 卸载

bash uninstall.sh
# nginx-upstream-dynamic-resolve-servers

[English](./README.md)  |  [中文](./README.cn.md)

一个可以在upstream块里动态解析域名的nginx模块

默认情况下，nginx只会在启动的时候解析一次upstream块里配置的域名。这个模块为 `server`指令提供了 `resolve`参数，可以异步解析upstream域名。如果你的upstream服务器的ip经常变动的化这个功能是非常有用的。另外，还提供了另外一个参数 `use_last`，使用这个参数可以让nginx在dns解析超时的时候使用上一次的结果。

如果你的域名不能正确解析，通常情况下nginx不会正常启动，使用了这个模块之后(`server`指令后面加 `resolve`,如果不加这个域名还是走原生的流程，不会动态解析)，我会在配置阶段把它替换成一个无用的ip，所以无需阻塞等待 `ngx_parse_url`函数的返回值，无需担心，我会在进程的启动阶段把域名换回来并且进行动态解析。

参考了https://github.com/GUI/nginx-upstream-dynamic-servers和https://github.com/zhaofeng0019/nginx-upstream-dynamic-resolve-servers的代码，解决内存使用的上的一些问题，详细可看下面的设计文档

 [设计文档中文](./doc/nginx_dynamic_server.md)

 [English Design Doc](./doc/nginx_dynamic_server_EN.md)

## 安装

应用patch

```c
patch -d ./ -p1 < ./nginx-upstream-dynamic-servers-1.22.0.patch
```

### 编译

```sh
./configure --add-module=/path/to/nginx-http-upstream-dynamic-servers
make && make install
```

## 使用

在upstream里面的 `server`指令的后面加上 `resolve`参数，`use_last`参数为可选

*注意：*

1. `http`块中必须定义 `resolver`
2. `use_last`参数必须在 `resolve`参数后面
3. 如果一个域名的 `server`配置项后面不加 `resolve`参数，那么它会走原生的流程也就是只解析一次并且如果这个域名不能正确解析，nginx不会启动

```
http {
  resolver 8.8.8.8;

  upstream example {
    server example.com resolve [use_last] ...;
    server test.com resolve [use_last] ...;
  }
}
```

# 兼容性

nginx 1.22

## 搭配选择

后端的健康模块使用的是：https://github.com/alexzzh/ngx_health_detect_module

## 许可协议

nginx-http-upstream-dynamic-servers 开源并使用 MIT 许可协议

# nginx-http-upstream-dynamic-servers

[English](./README.md)  |  [中文](./README.cn.md)



An nginx module to resolve domain names inside upstreams and keep them up to date.

By default, servers defined in nginx upstreams are only resolved when nginx starts. This module provides an additional `resolve` parameter for `server` definitions that can be used to asynchronously resolve upstream domain names. This keeps the upstream definition up to date according to the DNS TTL of each domain names. This can be useful if you want to use upstreams for dynamic types of domain names that may frequently change IP addresses. And there is another additional `use_last` parameter that can be used to make nginx to use the last result when DNS resolve timeout.

This module also allows nginx to start if an upstream contains a defunct domain name that no longer resolves. By default, nginx will fail to start if an upstream server contains an unresolvable domain name. With this module, nginx is still allowed to start with invalid domain names, but an error will be logged and the unresolvable domain names will be marked as down. if you add resolve parameter behind a server, it will be replaced to a useless ip at beginning. So it will not take a long time to wait for the result of ngx_parse_url in native process. Don't worry about this, it will be replaced back and to dynamic DNS resolve in the init_process.

Referenced the code from https://github.com/GUI/nginx-upstream-dynamic-servers and https://github.com/zhaofeng0019/nginx-upstream-dynamic-resolve-servers to resolve some memory usage issues. For details, please refer to the design document below.

 [设计文档中文](./doc/nginx_dynamic_server.md)

 [English Design Doc](./doc/nginx_dynamic_server_EN.md)

# Installation

Apply patch

```c
patch -d ./ -p1 < ./nginx-upstream-dynamic-servers-1.22.0.patch
```

## configure and make

```sh
./configure --add-module=/path/to/nginx-http-upstream-dynamic-servers
make && make install
```

# Usage

Use the `server` definition inside your upstreams and specify the `resolve` parameter.

*Note:*

1. A `resolver` must be defined at the `http` level of nginx's config for `resolve` to work.
2. The `use_last` parameter must behind `resolve` parameter.
3. For one domain, if you don't add `resolve` parameter in the `server` directive, the domain will just do nginx native process -- resolve just once and nginx will not start if the domain can't be resolved.

```
http {
  resolver 8.8.8.8;

  upstream example {
    server example.com resolve [use_last] ...;
    server test.com resolve [use_last] ...;
  }
}
```

# Attention

Since this situation won’t occur in actual use, it is not allowed for a server of a domain (e.g., `server test.com:9999`) to appear multiple times (either in the same upstream or across multiple streams).

The following two situations are not allowed:

```nginx
upstream a {
    server example.com:443 resolve;
    server example.com:443 resolve ;    
}
```

```nginx
upstream a {
    server example.com:443 resolve;
    server test.com:443 resolve ;    
}

upstream b {
    server example.com:443 resolve; 
}
```

The related code is in `ngx_http_upstream_dynamic_directive`:

```c
        if (NULL == node) {
			......
        } else {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "The server '%V' should not be used more than once in all "
                "upstream block",
                &dynamic_server->server->host);
            return NGX_ERROR;
        }
```

If it is indeed necessary, the key data of `udsmcf->rbtree` needs to be modified. For example, use `dynamic_server->host` and append the upstream name (this will require additional memory allocation for `dynamic_server->host`).

# Compatibility

Tested with nginx 1.22

# Complementary Choices

The backend health check module being used is: https://github.com/alexzzh/ngx_health_detect_module.

# License

nginx-http-upstream-dynamic-servers is open sourced under the MIT license.

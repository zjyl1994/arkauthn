# ArkAuthn

方舟认证，兼容 ForwardAuth 规范的认证服务。
可以兼容 Caddy 等实现了ForwardAuth的Web服务，基于 JWT 进行认证。

## 安装

1. 复制 `setup/arkauthn.service` 到 `/etc/systemd/system/arkauthn.service`
1. 编辑 `/etc/systemd/system/arkauthn.service`，指定 `WorkingDirectory`
1. 运行 `systemctl daemon-reload`
1. 运行 `systemctl enable arkauthn`
1. 运行 `systemctl start arkauthn`

运行后会在WorkingDirectory自动产生配置文件 `arkauthn.json`，默认用户为 `username`，密码为 `password`。
密码支持使用明文和bcrypt哈希两种方式存储。

## Caddy 配置
```caddyfile
auth.example.com {
    reverse_proxy http://localhost:9008
}
protect.example.com {
    forward_auth http://localhost:9008 {
        uri /api/forward-auth
    }
    respond "Protected Content"   
}
```

## JWT
JWT Payload 格式为：
```json
{
  "user": "zjyl1994",
  "exp": 1746549524,
  "nbf": 1746545924,
  "iat": 1746545924
}
```

## 支持的Token位置

|位置|字段|
|---|---|
|Header|`X-Arkauthn: <token>`|
|Cookie|`arkauthn=<token>`|

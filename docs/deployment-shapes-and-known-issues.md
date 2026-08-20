# 两种部署形态与已知问题

同一个 OpenVPN 需求有两种落地形态。本文说明如何选型，并记录 Web 形态在 `1545ba1` 上实测发现的代码问题。

## 形态对比

| | 本仓库（Docker + Web 管理台） | 原生 OpenVPN + systemd |
|:---|:---|:---|
| 管理方式 | 8833 端口的 Web 控制台 | 命令行脚本，或直接编辑账号文件 |
| 账号存储 | SQLite，密码 AES 可逆加密 | 纯文本文件 |
| 附加能力 | MFA、LDAP、邮件通知、连接历史、CCD、证书管理 | 需要什么自己写脚本 |
| 体量 | 容器，镜像约 59 MB，需要 `NET_ADMIN` | 一个包加几个脚本 |
| 适用 | 团队需要自助服务和管理界面 | Web 不允许暴露，或机器资源紧张 |

选型的分界线是**是否需要把管理界面暴露给使用者**。需要自助改密码、自助下载配置、自助设置 MFA，就用 Web 形态；只需要运维分发账号、用户拨号即可，原生形态更省事，攻击面也小得多。

## Web 形态的验证结论

在 Rocky/Debian 上用生产镜像完整跑过一遍，以下行为确认成立：

- 原生 HTTPS 按文档工作。证书落到 `/data/tls/`，权限 `0644` / `0600`；启用后明文 HTTP 打公网端口返回 400；内部监听保持在 `127.0.0.1:8834` 且回调仍是 HTTP。这个内部监听正是 HTTPS 不会打断 VPN 认证的原因，**`8834` 绝不能发布到宿主机**。
- `build/openvpn-web-*` 在 [.gitignore](../.gitignore#L12) 中，二进制不入库。全新克隆无法直接 `docker build ./build`，必须先按 CI 流程构建 Web UI 和两个架构的 Go 二进制。
- CI 推送的是 Docker Hub。生产使用的 ACR 镜像标签是手工构建推送的，发新版本是手工流程。

## 已知代码问题

### 1. 管理员密码不受密码策略约束

[`isValidPassword`](../src/openvpn-web/main.go#L393) 要求 12 位并包含大小写字母、数字、特殊字符。VPN 账号在 [`user.go:110`](../src/openvpn-web/user.go#L110)、`124`、`144` 三处都调用了它，但 `/settings` 里修改管理员密码的分支 [`main.go:823`](../src/openvpn-web/main.go#L823) 直接 bcrypt，没有校验。

结果是普通 VPN 账号被强制复杂密码，权限最高的管理员反而可以设成 `123456`。

修复方向：在该 case 内先调用 `isValidPassword`，不通过则返回 `passwordPolicyMessage()`。

### 2. 全新安装默认 `admin:admin`，且不强制改密

容器启动后 [`POST /login`](../src/openvpn-web/main.go#L614) 立即接受 `admin` / `admin` 进入后台，没有首次登录强制修改密码的环节。VPN 账号有 `IsFirstLogin` 字段和首次登录改密流程，管理员没有。

在端口对外暴露之前必须先改密码。更稳妥的做法是启动时生成随机密码写入 root 只读文件，或给管理员也加上首次登录强制改密。

### 3. VPN 账号密码可逆存储，且 API 直接返回明文

[`user.go:113`](../src/openvpn-web/user.go#L113) 用 `encryptUserPassword`（AES）而不是哈希，[`GET /ovpn/user`](../src/openvpn-web/main.go#L1107) 返回的 JSON 里 `password` 字段是解密后的明文。而 `secret_key` 与密文存在同一个 `config.json` 里。

这意味着拿到 `data` 目录等于拿到全部 VPN 账号明文密码。这是为了让后台能展示密码而做的设计取舍，不算 bug，但必须知道：**`data` 目录的备份要按凭证级别保管**，不能随手放进对象存储或代码仓库。

如果不需要「后台可查看密码」，改成 bcrypt 哈希可以彻底消除这个风险。

### 4. `GET /ovpn/history` 不带分页参数会生成非法 SQL

[`history.go:103`](../src/openvpn-web/history.go#L103) 直接拼 `Order(p.OrderColumn + " " + p.Order)`。当 `Params` 为零值时生成 `SELECT * FROM history ORDER BY   LIMIT 0`，SQLite 报语法错误。

Web UI 始终携带 `orderColumn` / `order` / `limit` / `offset`，走不到这条路径，所以不影响使用。但接口本身不健壮，直接调用或将来接入其他客户端时会踩到。

修复方向：对 `OrderColumn` 做白名单校验，为空时给默认排序字段，`Limit` 为 0 时给默认页大小。

### 5. healthcheck 首次启动刷 jq 报错

`deploy/tencent/docker-compose.yml` 的 healthcheck 读 `/data/config.json` 判断是否启用 HTTPS。首次启动的头几秒该文件还不存在，日志会出现 `jq: error: Could not open file /data/config.json`。`start_period` 覆盖了这段时间，不影响健康判定，只是日志噪音。

修复方向：在 jq 前加文件存在判断，或给 jq 加 `2>/dev/null` 并对空输出取默认值。

## 参考

- [部署与 HTTPS](deployment-and-https.md)

# Calabi —— 自建数据面

[English](self-hosting.md) · **中文**

Calabi 的**数据面是开源的**——三个二进制，它们之间提供两种访问「没有公网地址的
机器」的办法：

- `calabi-edge` 收公网流量，`calabi` 客户端把它转发到你本地的服务：**隧道**；
- `calabi-coord` 加上跑 relay 角色的 `calabi-edge`：你自己机器之间的私有
  WireGuard **组网**。见[组网](#组网)。

**控制面**（账号、组织、计费、托管在多个地域的边缘节点）是另一个闭源的托管产品。
本仓库就是数据面本身——它不回连、不需要账号，完全跑在你自己的机器上。

如果你只要隧道、也愿意自己跑一台边缘节点，那这份文档的前三分之二就够了。

```
┌─────────────┐        TLS + yamux        ┌──────────────┐      你的应用
│  calabi     │ ────────────────────────► │  calabi-edge │ ───►  127.0.0.1:8080
│  (客户端)   │   控制流 + 数据流         │  (你的 VPS)  │
└─────────────┘                           └──────────────┘
   你的笔记本                             公网 IP / 域名        访问者 ──┘
```

托管版 Calabi 在这之上还加了什么——账号、托管的多地域边缘节点、计费——列在下面的
*自建拿不到什么*。

## 目录

**隧道**

- [编译](#编译)
- [五分钟上手（一台边缘节点，一条隧道）](#五分钟上手一台边缘节点一条隧道)
- [边缘节点配置](#边缘节点配置)
- [客户端](#客户端)——[按隧道的安全策略](#按隧道的安全策略)
- [本地 supervisor 守护进程](#本地-supervisor-守护进程推荐)
- [本地 Web 控制台（`:7400`）](#本地-web-控制台7400)
- [HTTPS](#https)

**组网**

- [组网](#组网)——三个部件分别是什么
- [中继](#中继)
- [协调器](#协调器)
- [节点入网](#节点入网)
- [ACL](#acl)
- [子网路由与出口节点](#子网路由与出口节点)
- [非 Linux 上还没自动化的部分](#非-linux-上还没自动化的部分)

**然后**

- [自建拿不到什么](#自建拿不到什么)
- [上生产要注意的](#上生产要注意的)
- [许可证与贡献](#许可证与贡献)

---

## 编译

需要 Go 1.25+。

```bash
# 在仓库根目录
make build       # → bin/calabi, bin/calabi-edge, bin/calabi-coord
```

或者直接编（Windows 上把输出名写成 `*.exe`）：

```bash
( cd apps/client       && go build -o calabi       ./cmd/calabi )
( cd apps/calabi-edge  && go build -o calabi-edge  ./cmd/calabi-edge )
( cd apps/calabi-coord && go build -o calabi-coord ./cmd/calabi-coord )

calabi version   # → calabi <ver>
```

`make build` 在 Windows 上会自动加 `.exe`。在 Windows 上原生编出来的本来就是
Windows 二进制；要**交叉**编译到别的系统，设 `GOOS`/`GOARCH`（例如
`GOOS=windows GOARCH=amd64 go build -o calabi-edge.exe ./cmd/calabi-edge`）。

`calabi-coord` 只有组网才用得上；只要隧道的话另外两个就够。

---

## 五分钟上手（一台边缘节点，一条隧道）

**1. 起边缘节点**，放在有公网 IP 的主机上（想先试的话本地跑也行）。没有配置文件时
它接受演示 token `dev-token-please-change`，监听 `:7443`（控制）、`:8080`（HTTP）、
`:8443`（HTTPS，自签）和 `:9101`（管理口 `/healthz` + `/metrics`，别放公网）。它
不往外拨任何地址：内建默认值里根本没有控制面地址。

```bash
./calabi-edge           # CTRL-C 停止
```

> 试一下够用，但别就这么上：没有配置文件的边缘节点**不在** standalone 模式，
> 会忽略客户端发上来的按隧道安全策略。见下面的 [`mode`](#边缘节点配置)。

**2. 起一个要暴露的本地服务**：

```bash
python3 -m http.server 9000
```

**3. 起客户端**，指向你的边缘节点：

```bash
export CALABI_SERVER=127.0.0.1:7443       # 你边缘节点的控制端点
export CALABI_TOKEN=dev-token-please-change
export CALABI_INSECURE=1                   # 开发用：跳过对自签边缘节点的 TLS 校验
calabi http 9000 --domain app.localtest.me
```

**4. 通过边缘节点的 HTTP 监听访问**：

```bash
curl http://127.0.0.1:8080/ -H 'Host: app.localtest.me'
```

真要部署的话，把一条 DNS 记录指到边缘节点的公网 IP 并开放它的公网端口；见下面的
*上生产要注意的*。

---

## 边缘节点配置

边缘节点读一个可选的 YAML 文件（`./calabi-edge --config edge.yaml`）。自建时真正
用得上的字段：

```yaml
mode: standalone              # 要自己写上——它不是默认值，见下
node_label: my-edge           # 这台节点的名字
region: my-region             # 单节点部署时只是个标签
base_domain: tunnel.example.com   # 隧道域名形如 <name>.<base_domain>

control:
  addr: ":7443"               # 面向客户端的 TLS 监听（控制 + 数据）
  cert_pem: ""                # TLS 证书路径；留空 = 自签（开发用）
  key_pem: ""

http:
  addr: ":8080"               # 公网 HTTP 入口（访问者从这进）

https:
  addr: ":8443"               # 可选的 HTTPS 终止（见下面的 HTTPS）

admin:
  addr: ":9101"               # /healthz + /metrics——绑在内网

state:
  dir: ./state                # 持久化子域名计数器 + 自签证书

# 边缘节点在客户端 AUTH 帧里接受的 token，每个映射到一个租户。
accepted_tokens:
  - token: a-long-random-secret
    tenant_id: "1"
    workspace_id: default
    client_id: client-1
```

- **`mode`**——**记得设成 `standalone`**。它不是默认值，而且区别不只是好看：只有
  standalone 的边缘节点才会认客户端在 `NEW_PROXY` 里带上来的按隧道安全策略。不设的
  话，你的 `--ip-allow` / `--basic-auth` 客户端照收，边缘节点这边**静默忽略**——因为
  托管形态下策略来自控制面。`CALABI_EDGE_MODE=standalone` 可以不改 YAML 直接设。
- **`node_label` / `base_domain`**——两个都是节点级字段，也都换过位置：原来叫
  `node_id`（和意思完全不同的 `edge_node_id` 只差一个字）和 `http.base_domain`
  （读它的远不止 HTTP 监听——子域名分配器、TCP 端点命名、自签泛域名、控制握手都读）。
  **旧写法仍然能加载**，现成的 `edge.yaml` 不用动；但两种写法都写、值又不一样的话，
  启动时会直接报错，而不是悄悄挑一个。
- **`accepted_tokens`**——你的认证。可热加载：改文件即生效，不用重启（`base_domain`
  同理）。其余字段都是要重启的；一次改动里只要碰到其中之一，整次热加载会被拒绝并打
  日志——所以不会出现「改了一半」。

---

## 客户端

`calabi http|tcp|udp` 各开一条隧道并停在前台。

```bash
calabi http 8080  --domain app.example.com
calabi tcp  22    --remote-port 2222
calabi udp  53    --remote-port 5353
```

环境变量：

| 变量 | 含义 |
|---|---|
| `CALABI_SERVER` | 边缘节点控制端点 `host:port`（默认 `localhost:7443`） |
| `CALABI_TOKEN` | 边缘节点 `accepted_tokens` 里的某个 token |
| `CALABI_INSECURE=1` | 跳过 TLS 校验（自签的边缘节点） |
| `CALABI_EDGE_CA_FILE` | 改用这个 CA 去校验边缘节点证书 |

### 按隧道的安全策略

所有按隧道的访问控制都在这个二进制里：**IP 黑白名单**（所有隧道类型）、
**HTTP Basic 认证**、**连接限速**、**请求头改写**，以及 **OAuth 登录墙**
（Google / GitHub）——后三项只对 HTTP 生效。密码在**本地**就用 bcrypt 哈希过，
明文不会离开你的机器：

```bash
calabi http 8080 --domain app.example.com \
  --ip-allow 10.0.0.0/8 --ip-deny 1.2.3.4 \
  --basic-auth alice:s3cret --basic-auth bob:hunter2 \
  --security-file policy.json      # 或者一整个 {"security":{…}} 结构
```

边缘节点会对那条隧道执行这些策略（IP 黑白名单 + Basic 认证）。

> 自建的边缘节点执行的策略集和托管的完全一样。托管产品里这些功能按**套餐**
> 门控，那道门在控制面里，不在这份代码里。

---

## 本地 supervisor 守护进程（推荐）

与其一个终端跑一条 `calabi http`，不如用一个配置文件、一个进程管**所有**隧道，
并且断线自动重连：

```bash
calabi daemon --config tunnels.yaml
```

`tunnels.yaml`（完整带注释的版本见
[`docs/examples/tunnels.yaml`](examples/tunnels.yaml)）：

```yaml
server: edge.example.com:7443
token: ${CALABI_TOKEN}           # 字面量，或用 ${ENV_VAR} 从环境变量读
# insecure: true                 # 见下面的 TLS 说明（不写就会校验证书）
# ca_file: /path/to/edge-ca.pem  # 钉住边缘节点的 CA，才是真的在校验
tunnels:
  - name: app
    type: http
    local: 127.0.0.1:8080
    domain: app.example.com
    security:
      ip_allow: ["10.0.0.0/8"]
      basic_auth: ["admin:s3cret"]   # 加载时 bcrypt 哈希
  - name: ssh
    type: tcp
    local: 127.0.0.1:22
    remote_port: 2222
```

装成开机自启的系统服务（Windows 服务 / systemd / launchd）：

```bash
calabi daemon install --config tunnels.yaml   # 然后：calabi daemon start|stop|status
```

> **服务相关的坑。** 装好的服务会在崩溃后和开机时自动拉起（Windows 服务
> `OnFailure=restart`、systemd `Restart=always`、launchd `KeepAlive`）。以服务身份
> 运行时它没有「用户主目录」，所以日志写在 `calabi` 二进制旁边（不在你的用户
> 目录下）。**改 `--config`（或配置文件路径）必须
> `calabi daemon uninstall` + 重新 `install` 才生效**——启动参数是安装时就烧进去的。

> `tunnels:` 可以是空的（`tunnels: []`）。守护进程照样会连上并提供控制台——可以
> 一条隧道都不配就启动，然后**在浏览器里建**（见下），建好会写回你的
> `tunnels.yaml`。

> **TLS / 自签的边缘节点。** 自建的边缘节点是自签证书。本地守护进程因此
> **默认跳过对边缘节点的 TLS 校验**（会打一条警告日志），而不是硬要一个 CA——这样
> 在可信网络里开箱即用。想真的校验，把 `ca_file:` 指到它的 CA PEM（或用
> `CALABI_EDGE_CA_FILE`）。写 `insecure: true` 表示你明确要跳过（顺便消掉那条警告）。

---

## 本地 Web 控制台（`:7400`）

只要有隧道或本地守护进程在跑，浏览器打开 **http://127.0.0.1:7400** 就是一个面板：

- 隧道列表 + 实时流量计数；
- **请求检查器**（按连接的日志 + HTTP 请求/响应抓取）；
- 守护进程日志；
- 以及——配合本地守护进程——**新建 / 删除隧道、实时改每条隧道的安全策略**，
  改动写回你的 `tunnels.yaml`。

控制台只和本地守护进程通信（loopback），不需要账号，也不会往控制面发任何请求。
改某条隧道的策略只会重新注册那一条——其他隧道的连接不受影响。

> 控制台的编辑会重写 `tunnels.yaml`（你的 `server` / `token` / TLS 配置原样保留
> ——`token: ${CALABI_TOKEN}` 这种写法能让密钥不落到文件里；但**注释不会保留**，
> 而且会加一行「由控制台管理」的头）。如果这个文件在版本控制里、或者你手写了注释，
> 那就直接改 YAML、让守护进程去 reload。

---

## HTTPS

自建的边缘节点可以在 `https.addr` 上终止 HTTPS，但它需要一张证书。目前的选项：

1. **自带证书**——把 `control.cert_pem`/`key_pem` 指过去（控制监听用），HTTPS 证书
   通过 `state.dir` 或一张真证书提供；适合你自己控制的域名。
2. **自签泛域名**（开发用）——设了 `base_domain` 且没有别的证书来源时，边缘节点会
   在 `state.dir` 下生成一张自签泛域名证书。浏览器会告警，除非你导入它。这条默认就
   开着：`https.addr` 默认 `:8443`，所以没有配置文件的边缘节点已经在用生成的证书
   提供 HTTPS。

> **已知缺口**：自建边缘节点上的自动 Let's Encrypt（ACME）还没做——在路线图上。
> 在那之前用上面两个选项之一。

---

## 组网

隧道是把公网引进来。组网正好相反：它把**你自己的**机器连成一张私有 WireGuard
网络——稳定的 `100.64.0.0/10` 地址（跟着机器换网络也不变）、NAT 允许时的
点对点直连路径，以及打不通时你自己跑的中继。

三块：

| | | |
|---|---|---|
| `calabi-coord` | 协调器 | 节点注册、地址分配、ACL、MagicDNS、中继目录 |
| `calabi-edge` 配 `role: relay` | 中继 | 按节点公钥转发**已经加密好的**报文，并响应 STUN 让节点找到自己的公网端点 |
| `calabi mesh up` | 节点 | 本地生成 WireGuard 密钥、入网、拉起 tun 设备 |

协调器拿不到私钥，也看不到明文。中继同样：它按节点公钥路由密文，代码里根本没有
能解密的路径——这个隔离是**结构性**的（`pkg/relay` 不携带任何 edge / 控制面代码，
由依赖关系测试钉死），不是一个配置开关。

### 中继

中继不需要任何配置文件——没有域名、没有证书、没有要终止的东西：

```bash
CALABI_EDGE_ROLE=relay CALABI_EDGE_RELAY_LABEL=home ./calabi-edge
```

它监听 **3340/tcp**（中继本身）和 **3478/udp**（STUN）。两个都得让你的节点能连到。
用 YAML 的话：

```yaml
role: relay          # 或 "both"：一个进程同时跑隧道边缘和中继
relay:
  derp_port: 3340
  stun_port: 3478    # 0 = 关掉 STUN 响应
  label: home        # 给这个 region 命名；节点归属到 "self-home"
```

> 没设 `label` 的中继能起来，但会告警：它没法注册进中继目录，所以永远不会有节点
> 归属到它。

想跑几台就跑几台、放在不同地方；节点会用 STUN 测到各个中继的延迟，自己挑。

### 协调器

```bash
CALABI_COORD_AUTHKEYS_FILE=./authkeys.json \
CALABI_COORD_DERP_ADDR=relay.example.com:3340 \
CALABI_COORD_DERP_STUN_PORT=3478 \
./calabi-coord
```

| 变量 | 作用 |
|---|---|
| `CALABI_COORD_GRPC_ADDR` | 节点连过来的地址。默认 `:7012` |
| `CALABI_COORD_ADMIN_ADDR` | 健康检查 + 指标。默认 `:9122`；别放到公网 |
| `CALABI_COORD_AUTHKEYS_FILE` | **认证密钥。** JSON：`{"key": {"meshnet": 1, "tags": ["tag:laptop"]}}` |
| `CALABI_COORD_DERP_ADDR` | 只有一台中继时的简单写法：`host:port` |
| `CALABI_COORD_DERP_STUN_PORT` | 那台中继的 STUN 端口。不写的话这个 region 没法被测量，就永远没人归属到它 |
| `CALABI_COORD_DERP_MAP_FILE` | 多台中继：一个 JSON 目录（见 `apps/calabi-coord/examples/derp-map.example.json`） |
| `CALABI_COORD_POLICY_FILE` | ACL 文件。不设 = 同一张网里的节点互相全通 |
| `CALABI_COORD_NODE_QUOTA` | 每张网的节点数上限。不设 = 无限 |
| `CALABI_COORD_DB_DSN` | 状态存哪。`sqlite:./coord.db` 存成一个文件，或者给一个 `postgres://…` URL。**不设 = 存内存里**，见下 |
| `CALABI_COORD_TLS_CERT_FILE` / `_KEY_FILE` | gRPC 走 TLS。要么都设，要么都不设 |
| `CALABI_COORD_MESH_ADMIN_ADDR` / `_TOKEN` | 管理 HTTP API。**没有 token 的管理接口会在启动时被拒绝**——它会把每一张网的节点和 ACL 全暴露出去 |

一个 `meshnet` 就是一张互相隔离的网。两把密钥映射到不同的 meshnet 编号，就是同一个
协调器上两张互相看不见的网。

> **给它一个数据库。** 不设 `CALABI_COORD_DB_DSN` 的话，节点注册表、ACL 文档、
> 声明的服务、自建中继目录全在**内存**里——启动时它会自己说一声——意思是重启一次注册表
> 就空了：每个节点重新入网，拿到的是**另一个** `100.64.x.x` 地址。
> `CALABI_COORD_DB_DSN=sqlite:./coord.db` 就够，不需要 Postgres。DSN 设了但连不上
> 会直接启动失败，而不是回落到内存。

> 设 `CALABI_ENV=production`，协调器会在任何一个「失败放行」的兜底还生效时拒绝启动
> ——最重要的是那把内建的默认认证密钥，它会把**任何**调用者放进 meshnet 1。
> 凡是公网能碰到的部署都该设上。

### 节点入网

```bash
sudo ./calabi mesh up \
  --coord coord.example.com:7012 \
  --relay relay.example.com:3340 \
  --auth-key my-secret-key --name laptop
```

需要 tun 设备和管理员权限。Windows 上 `wintun.dll` 已经内嵌在二进制里，不用装任何
东西。节点的 WireGuard 密钥在本地生成并缓存（用 `--key-file` 指定位置）；重复运行
保持同一个身份，因此也保持同一个 `100.64.x.x` 地址。

`calabi mesh status` 和 `calabi mesh down` 是通过 `:7400` 和正在跑的守护进程说话的。
想让组网以后台服务方式跑（而不是前台），把它写进守护进程配置再装成服务：

```yaml
mesh:
  enabled: true
  coord: coord.example.com:7012
  relay: relay.example.com:3340
  auth_key: my-secret-key
  name: laptop
```

> 和隧道的 `token:` 不一样，`auth_key:` **没有** `${ENV_VAR}` 这种写法——它是按字面量
> 读的。把文件权限收紧（它是一份凭据），或者干脆前台跑 `calabi mesh up`、密钥写在
> 命令行上。

> **节点到协调器这段的 TLS。** 节点默认用 TLS 连协调器，并用编译进客户端的 CA
> 校验它，所以自建的协调器需要二选一：给它签一张你自己 CA 的证书
> （`CALABI_COORD_TLS_CERT_FILE`/`_KEY_FILE`），节点侧用
> `CALABI_EDGE_CA_FILE=/path/to/your-ca.pem` 指过去；或者在节点上设
> `CALABI_INSECURE=1` 走明文。**认证密钥是从这条连接上发过去的**，所以明文只适合
> 可信网络。如果两个证书变量只设了一个，协调器会拒绝启动，而不是悄悄地提供明文服务。

### ACL

不设 `CALABI_COORD_POLICY_FILE` 时，同一张网里的节点互相全通。设了之后，一个由
分组和规则组成的 JSON 文件决定谁能访问谁的哪些端口。改文件会热加载——而且文件
写坏时它**失败关闭**（全部拒绝）并大声报错，绝不退回「全放行」。把文件改好，
不用重启就能恢复。

### 子网路由与出口节点

```bash
calabi mesh up ... --advertise-routes 192.168.1.0/24   # 把一个局域网共享给整张网
calabi mesh up ... --advertise-exit-node               # 声明自己可以当出口节点
calabi mesh up ... --exit-node home-server             # 把「我」的默认路由从某个对端走出去
```

**通告**在所有平台都能用。真正做转发的那一半——打开 IP 转发和 NAT 让包能穿过去
——**只在 Linux 上是自动配好的**；其他平台上节点照样通告，但操作系统那边要你自己配。
作为出口节点*客户端*接管默认路由，在 Linux、Windows、macOS 上都可以。

### 非 Linux 上还没自动化的部分

MagicDNS 的操作系统集成（分配解析器地址 + 改写系统 resolver 配置）目前只有 Linux。
组网本身在所有平台都能用——节点**地址**各平台都正常——但节点**名字**只有在 Linux
上才能通过操作系统解析。

---

## 自建拿不到什么

下面这些是控制面的功能。命令在二进制里存在，但没有托管账号就什么也做不了：

- `calabi login / logout / org / certs / domains / clients`；
- 托管的在线状态 / CONFIG_PUSH 同步守护进程（本地 supervisor
  `calabi daemon --config …` 是自建版的等价物）；
- 托管的多地域边缘发现 / 全球边缘节点；
- 账号、组织、计费、console.\<host\> 上的 Web 控制台。

这些都在托管产品里。本仓库里的客户端、边缘节点和协调器本身，已经是一套完整的、
可独立运行的隧道**和**组网栈。

注意**不在**这份清单上的东西：组网。`calabi-coord` 是一个完整的协调器，不是演示品
——它有自己的认证密钥、自己的 ACL、自己的中继目录。托管平台换掉的是它*信任谁的账号*
（用组织身份代替一个密钥文件）以及计量；组网本身就是这份代码。反过来也成立：自建的
协调器只属于你，不能接进托管平台的节点，而托管平台的用户也从来不需要自己跑一个。

---

## 上生产要注意的

- 把边缘节点放在公网 IP / 域名后面。开放 `control.addr`（客户端连它）和
  `http.addr` / `https.addr`（访问者连它）。`admin.addr`（`:9101`，`/metrics`
  `/healthz`）留在内网接口上。
- 把 `state.dir` 设成一个可写路径，子域名计数器和自签证书才能跨重启保留。
- 轮换 `accepted_tokens` 直接改文件即可（热加载）。
- 进程级的背压上限可以用环境变量设（`EDGE_GLOBAL_MAX_CONNS`、
  `EDGE_GLOBAL_ACCEPT_RATE_PER_SEC`）。
- 用服务管理器跑客户端 / 守护进程（`calabi daemon install`），这样开机会自动起。

---

## 许可证与贡献

按 [LICENSE](LICENSE)（另见 `NOTICE`）开源。欢迎给边缘节点核心、客户端核心和本地
控制台提 issue 和补丁。

# Calabi —— 自建

[English](self-hosting.md) · **中文**

Calabi 的**数据面是开源的**——三个二进制。其中两个是你的服务器，第三个跑在你的每台设备上：

- `calabi-coord`，协调器：设备在这里入网、分到 `100.64.x.x` 地址、找到彼此；手机 App 和各台机器的
  控制台也从这里看到组网里的设备、隧道和流量；
- `calabi-edge`，边缘节点：为你的**隧道**接公网流量，并在设备之间无法直连时为**组网**中继流量；
- `calabi`，客户端：提供隧道、加入私有 WireGuard 组网。

协调器是每台设备的身份。设备用邀请入网一次，之后由协调器告诉它边缘节点在哪、并签发边缘节点认的凭证。
所以同一台设备既有隧道也有组网；在设备上关掉组网，隧道照常。

```
                        ┌────────────────┐
     入网；拿到边缘节点 │  calabi-coord  │  设备、地址、ACL、邀请
     地址和凭证         │   (你的服务器) │
          ┌────────────►└────────────────┘
          │
    ┌─────┴─────┐    隧道     ┌────────────────┐
    │  calabi   │ ──────────► │  calabi-edge   │ ◄──── 访问者（HTTP / TCP / UDP）
    │  (设备)   │             │   (你的服务器) │
    └─────┬─────┘             └────────────────┘
          │  WireGuard：直连，或经边缘节点的中继
          ▼
      你的其他设备
```

**控制面**（账号、组织、计费、托管在多个地域的边缘节点）是另一个闭源的托管产品。这三个程序不回连、
不需要账号，完全跑在你自己的机器上。`apps/client-android` 里的 Android App 和客户端自带的控制台也能连你自己的服务器，
见[手机和桌面控制台](#手机和桌面控制台)。

## 目录

- [用 Docker 快速起一台服务器](#用-docker-快速起一台服务器)
- [获取程序](#获取程序)

**你的服务器**

- [协调器](#协调器)——[它的证书](#协调器的证书)
- [边缘节点](#边缘节点)——[HTTPS](#https)、[单独一台中继](#单独一台中继)
- [邀请和设备](#邀请和设备)
- [协调器和边缘节点分开部署](#协调器和边缘节点分开部署)

**设备**

- [入网](#入网)
- [隧道](#隧道)——[安全策略](#按隧道的安全策略)、[守护进程](#守护进程)、[控制台](#本地-web-控制台7400)
- [组网](#组网)——[ACL](#acl)、[子网路由与出口设备](#子网路由与出口设备)
- [手机和桌面控制台](#手机和桌面控制台)

**然后**

- [自建拿不到什么](#自建拿不到什么)
- [上生产要注意的](#上生产要注意的)
- [从 1.12 及更早版本升级](#从-112-及更早版本升级)
- [许可证与贡献](#许可证与贡献)

---

## 用 Docker 快速起一台服务器

在一台有公网地址、装了 Docker Compose（或 `podman compose`）的 Linux 机器上，[`deploy/server`](../deploy/server)
这个捆绑包用一份 `.env` 把协调器和边缘节点一起跑起来：

```bash
cd deploy/server
cp .env.example .env     # 填 CALABI_PUBLIC_HOST、CALABI_ADMIN_TOKEN；要 HTTP 隧道再填 CALABI_TUNNEL_DOMAIN
docker compose up -d
docker compose exec coord calabi-coord invite --note "我的笔记本"
```

对公网开放这些端口：

| 端口 | 用途 |
|---|---|
| 7012/tcp | 设备 ↔ 协调器 |
| 7443/tcp | 设备的隧道连接 |
| 80/tcp、443/tcp | HTTP 隧道的访问者 |
| 20000–20999/tcp 和 /udp | TCP、UDP 隧道的访问者 |
| 3340/tcp、3478/udp | 组网中继和 STUN |

HTTP 隧道还需要把隧道域名的泛解析（`*.tunnels.example.com`）指向这台机器。

在电脑上，用邀请打印的链接入网，然后开一条隧道：

```bash
calabi join "calabi://join?…"
calabi http 8080
```

手机 App 则扫邀请的二维码。捆绑包的 [README](../deploy/server/README.md) 讲设备管理、升级和备份；本页其余部分是它底下
在做什么，以及每一项设置。

---

## 获取程序

每个版本的[发布页](https://github.com/calabinet/calabi/releases)都有这三个程序的 Linux（amd64、arm64、armv7）、
macOS 和 Windows 版，附带能从这份源码重新构建并比对的 `build-manifest.json`。`calabi-edge` 和 `calabi-coord`
也有 Docker 镜像：`calabinet/calabi-edge`、`calabinet/calabi-coord`（amd64、arm64）。

自己编译（Go 1.25+）：

```bash
# 在仓库根目录
make build       # → bin/calabi、bin/calabi-edge、bin/calabi-coord
```

或者直接编（Windows 上把输出命名为 `*.exe`）：

```bash
( cd apps/client       && go build -o calabi       ./cmd/calabi )
( cd apps/calabi-edge  && go build -o calabi-edge  ./cmd/calabi-edge )
( cd apps/calabi-coord && go build -o calabi-coord ./cmd/calabi-coord )
```

交叉编译设 `GOOS`/`GOARCH`（例如 `GOOS=windows GOARCH=amd64 go build -o calabi-edge.exe ./cmd/calabi-edge`）。

服务器、边缘节点和客户端应当用同一个版本：设备要 1.13 或更新才能入网，本页写的都是 1.13。

---

## 协调器

```bash
CALABI_COORD_DB_DSN=sqlite:./coord.db \
CALABI_COORD_MESH_ADMIN_ADDR=127.0.0.1:9500 \
CALABI_COORD_MESH_ADMIN_TOKEN=a-long-random-secret \
CALABI_COORD_PUBLIC_ADDR=server.example.com:7012 \
CALABI_COORD_EDGE_ADDR=server.example.com:7443 \
CALABI_COORD_GRANT_PUBKEY_FILE=./coord.pub \
CALABI_COORD_DERP_ADDR=server.example.com:3340 \
CALABI_COORD_DERP_STUN_PORT=3478 \
./calabi-coord
```

| 变量 | 作用 |
|---|---|
| `CALABI_COORD_GRPC_ADDR` | 设备连到这里。默认 `:7012` |
| `CALABI_COORD_PUBLIC_ADDR` | 设备拨的地址，`host:port`——邀请链接里带的就是它 |
| `CALABI_COORD_DB_DSN` | 状态存在哪。`sqlite:./coord.db` 存文件，或一个 `postgres://…`。**不设 = 放内存**，见下 |
| `CALABI_COORD_MESH_ADMIN_ADDR` / `_TOKEN` | 管理 HTTP API，`calabi-coord invite`、`authkey`、`device` 都经它。绑在内网地址上。**没有令牌的管理接口在启动时就会被拒绝** |
| `CALABI_COORD_ADMIN_ADDR` | 健康检查和指标。默认 `:9122`，不要对外 |
| `CALABI_COORD_EDGE_ADDR` | 设备开隧道用的边缘节点，它控制端口的 `host:port` |
| `CALABI_COORD_EDGE_PIN` | 这台边缘节点的证书指纹（`calabi-edge -fingerprint`）。不设：协调器自己去边缘节点读，见下 |
| `CALABI_COORD_EDGE_TRUST` | `system` 表示边缘节点用的是公开受信的证书：不下发指纹，设备按系统根证书核对 |
| `CALABI_COORD_EDGE_PROBE_ADDR` | 协调器自己连边缘节点读证书用的地址，和 `EDGE_ADDR` 不同时才设（同机是 `127.0.0.1:7443`，compose 网络里是 `edge:7443`） |
| `CALABI_COORD_RELAY_GRANT_KEY_FILE` | 协调器签凭证用的密钥。默认 `./coord-grant.key`，首次启动时生成 |
| `CALABI_COORD_GRANT_PUBKEY_FILE` | 每次启动把这把密钥的公钥写到这个文件，给读它的边缘节点 |
| `CALABI_COORD_DERP_ADDR` | 一台中继，最简单的情况：`host:port` |
| `CALABI_COORD_DERP_STUN_PORT` | 这台中继的 STUN 端口。不设就测不了这个区域，也就没有设备会把它当主中继 |
| `CALABI_COORD_DERP_HOME_REGION` | `CALABI_COORD_DERP_ADDR` 这个区域的名字（默认 `default`）；用了映射文件而文件没写 `home_region` 时，是新设备起步的区域 |
| `CALABI_COORD_DERP_MAP_FILE` | 多台中继：一个 JSON 目录（见 `apps/calabi-coord/examples/derp-map.example.json`） |
| `CALABI_COORD_AUTHKEYS_FILE` | 你自己的永久入网密钥，可选。JSON：`{"key": {"meshnet": 1, "tags": ["tag:laptop"]}}` |
| `CALABI_COORD_POLICY_FILE` | ACL 文件。不设 = 同一个组网里每台设备都能访问其他所有设备，见 [ACL](#acl) |
| `CALABI_COORD_NODE_QUOTA` | 每个组网的设备上限。不设或 `0` = 不限 |
| `CALABI_COORD_TLS_CERT_FILE` / `_KEY_FILE` | 用这张证书提供 gRPC。要么都设、要么都不设。都不设 = 自签证书，见[它的证书](#协调器的证书) |
| `CALABI_COORD_TLS_DIR` | 自签证书放在哪。默认 `./coord-tls` |
| `CALABI_COORD_TLS` | `off` 表示明文 |

**凭证。** 说一台设备是谁的只有协调器。它给每台设备签一份凭证——设备的公钥、所属组网、一小时后到期——
边缘节点只接受出示凭证、并能证明自己持有凭证上那把私钥的设备，隧道和中继都是这样。设备在凭证到期前自己续。
`calabi-coord pubkey` 打印这把签名密钥的公钥：交给边缘节点，或者让协调器写到 `CALABI_COORD_GRANT_PUBKEY_FILE`，
由边缘节点从那里读。**保管好 `coord-grant.key`**：换一把就是换一个公钥，还拿着旧公钥的边缘节点会把所有设备拒之门外。

**它告诉设备的边缘节点。** 设备向协调器要边缘节点的地址和指纹，并钉住这个指纹。没设 `CALABI_COORD_EDGE_PIN` 时，
协调器会连上边缘节点读它出示的证书——读到之前每几秒一次，读到之后每分钟一次——所以边缘节点换了证书，设备会自己跟上，
不需要谁确认；协调器会记一条日志。读到之前它不告诉设备任何边缘节点，免得设备用别的方式去核对一张自签证书。
这种「自己去读」只适合两者之间的路径没法被篡改的情况——同一台机器、同一个 compose 网络；否则请给 `CALABI_COORD_EDGE_PIN`。

一个 `meshnet` 就是一张相互隔离的组网。两把密钥对应不同的 meshnet 编号，就是同一个协调器上互相看不见的两张网。

> **给它一个数据库。** 不设 `CALABI_COORD_DB_DSN` 时，协调器把设备登记、ACL、声明的服务和中继目录都放在
> **内存**里——启动时会明说，也就意味着一重启登记就清空：每台设备都要重新入网，还会分到*不同的* `100.64.x.x` 地址。
> `CALABI_COORD_DB_DSN=sqlite:./coord.db` 就够了，不要求 Postgres。设了但用不了的 DSN 会让启动失败，而不是退回内存。
> 既没有密钥文件也没有数据库时，协调器接受一个内置密钥 `dev-meshnet-1-key` 入组网 1——给你在自己机器上先试试。

> 设 `CALABI_ENV=production`，协调器遇到任何失败即放行的默认值都会拒绝启动——最要紧的是那把内置密钥，它能让*任何人*
> 进组网 1，所以需要密钥文件或数据库。它还要求设了 `CALABI_COORD_NODE_QUOTA`（`0` 表示不限）。凡是公网能访问到的，都这样设。

### 协调器的证书

**邀请里的密钥要经过设备到协调器这段连接**，所以协调器提供 TLS。没有 `CALABI_COORD_TLS_CERT_FILE`/`_KEY_FILE`
时，它首次启动生成一张自签证书，放在 `CALABI_COORD_TLS_DIR`。保留这个目录：新证书就是新指纹，钉了旧指纹的设备
会连不上，直到有人在设备上确认新的。`calabi-coord fingerprint` 打印指纹，邀请里也带着它。

设备怎么核对协调器的证书（配置里的 `trust:`，`calabi mesh up` 的 `--trust`）：

| trust | 核对什么 | 怎么设 |
|---|---|---|
| `pin` | 证书的公钥是否等于某个指纹；不核对主机名 | 邀请里的指纹、`pins:`、`--pin` |
| `system` | 操作系统信任的根证书和主机名——用 Let's Encrypt 证书的协调器 | 邀请没带指纹时的默认 |
| `ca` | 只信你的 CA，并核对主机名 | `ca_file:`、`--ca-file` |
| `plaintext` | 什么都不核对 | `trust: plaintext`、`--trust plaintext` |

连你自己的协调器时，永远不信编进客户端里的那张 CA——那是 calabi.net 的。`CALABI_COORD_TLS=off` 表示明文——
用于你信任的网络，或前面有代理终止 TLS。这种协调器的邀请要用 `calabi-coord invite --allow-plaintext` 生成，
链接里会写明；在 App 里手填这种协调器的地址，要勾上**不加密**。

---

## 边缘节点

边缘节点读一个 YAML 文件（`./calabi-edge -config edge.yaml`）：

```yaml
mode: standalone             # 属于你自己的协调器；必填
role: both                   # 隧道和组网中继在一个进程里
coord_pubkey_file: ./coord.pub   # 协调器的凭证公钥（或 coord_pubkey: <base64>）
node_label: my-server        # 这个节点在日志里的名字
base_domain: tunnels.example.com  # HTTP 隧道成为 <名字>.<base_domain>

control:
  addr: ":7443"              # 设备连这里
  cert_pem: ""               # 证书；留空 = 自签，放在 state.dir
  key_pem: ""

http:
  addr: ":80"                # 访问者
https:
  addr: ":443"               # 见下面的 HTTPS

relay:
  derp_port: 3340            # 中继
  stun_port: 3478            # 0 关掉 STUN
  label: my-server           # 这台中继在日志里的名字

admin:
  addr: "127.0.0.1:9101"     # /healthz + /metrics——不要对外

state:
  dir: ./state               # 子域名计数器和自签证书
```

- **`mode: standalone`**——这台边缘节点属于你运行的协调器。它只凭这个协调器的凭证接受设备（没有 token，
  没有控制面），应用每条隧道的客户端发来的安全策略，也允许客户端在 `base_domain` 下自己选名字。
  跑隧道却没写 `mode: standalone` 的边缘节点会拒绝启动。
- **`coord_pubkey` / `coord_pubkey_file`**——协调器的凭证公钥，直接写（`calabi-coord pubkey` 打印它），
  或者写协调器导出的那个文件。必填。文件还不存在时边缘节点会等——和协调器一起启动时，它会比协调器晚一点起来。
  环境变量 `CALABI_EDGE_COORD_PUBKEY` / `CALABI_EDGE_COORD_PUBKEY_FILE` 也能设。（`relay.coord_pubkey` 是旧写法，
  两者必须一致。）
- **证书。** 没有 `control.cert_pem`/`key_pem` 时，边缘节点首次启动生成一张自签证书，放在 `state.dir`
  （`control.crt`、`control.key`）；`./calabi-edge -config edge.yaml -fingerprint` 打印它的指纹。设备的指纹来自协调器，
  所以换了证书设备会自己跟上。连 `state.dir` 也没有时，每次启动都换一张新证书，并给出警告。
- **TCP 和 UDP 隧道**的公网端口从 20000–20999 里分配，除非客户端指定了别的（`--remote-port`、`remote_port:`）——那个端口也要开放。
- **热加载。** `base_domain` 可以在运行中改（编辑文件即可）；其他字段只在启动时读，改了其中任何一个，整次重载都会被拒绝并记日志。
- **旧键。** `node_id` 和 `http.base_domain` 是 `node_label`、`base_domain` 的旧写法，照样能读；两种写法都写了且值不同会被拒绝。
  `accepted_tokens` 已删除：空列表会被忽略，仍列着 token 的文件会被拒绝——设备凭凭证登录。

### HTTPS

设了 `base_domain`、又没有自己的证书时，边缘节点在 `https.addr` 上用它在 `state.dir` 下生成的自签泛域名证书
（`edge-https.crt`）提供 HTTPS。浏览器会警告，除非你导入这张证书。自建边缘节点自动申请 Let's Encrypt 证书还没有做。

### 单独一台中继

放在别处、离你某些设备更近的中继，就是 `role: relay` 的边缘节点，不需要配置文件：

```bash
CALABI_EDGE_MODE=standalone CALABI_EDGE_ROLE=relay \
CALABI_EDGE_RELAY_LABEL=tokyo CALABI_EDGE_COORD_PUBKEY=<calabi-coord pubkey> \
./calabi-edge
```

它监听 3340/tcp 和 3478/udp，只为持有你协调器凭证的设备服务。把它写进协调器的 `CALABI_COORD_DERP_MAP_FILE`，
或经管理 API 登记；设备通过 STUN 测每台中继，选最近的作为主中继。中继按设备公钥转发密文，没有任何能解密的代码路径——
这种隔离是结构上的（`pkg/relay` 不含边缘节点或控制面代码，有依赖测试守着）。

---

## 邀请和设备

管理命令经运行中的协调器的管理 API 执行，用同样的环境变量（或 `--admin`、`--token`）：

```bash
./calabi-coord invite --note "小明的手机"
```

它打印一条 `calabi://join?…` 链接、一个二维码，以及等价的 `calabi join "…"` 命令行。默认一份邀请**只放进一台设备**、
**24 小时内**有效：`--uses 5`、`--reusable`、`--expires 72h`、`--no-expiry` 改变这些，`--tag tag:phone` 给它放进的
每台设备打上 ACL 标签。协调器用自签证书时，链接里带着它的指纹；链接里也带着密钥：只发给要用它的人。

```bash
./calabi-coord authkey create --reusable --no-expiry --tag tag:server   # 只要密钥、不要链接
./calabi-coord authkey list
./calabi-coord authkey revoke 3            # 不再让新设备用它入网

./calabi-coord device list
./calabi-coord device disable 5            # ID 那一列；`enable 5` 恢复
./calabi-coord device delete 5
./calabi-coord device approve 5            # 组网要求审批时
```

密钥只负责放设备进来，不跟着设备。入网后，设备靠证明自己持有设备私钥回来，所以吊销密钥只挡新设备，不移除任何设备。
**要移除设备，就停用或删除它。** 它立刻离开组网；它的隧道在它手里的凭证到期时停止，最多一小时
（边缘节点离线核对凭证，不会收到协调器的通知）。删除的设备要新的邀请才能回来。每把密钥只存哈希；密钥本身只在生成时显示一次。

---

## 协调器和边缘节点分开部署

- 协调器需要 `CALABI_COORD_EDGE_ADDR`（边缘节点的公网地址），而且它不该相信经公网读到的东西，所以还需要
  `CALABI_COORD_EDGE_PIN`——在边缘节点上 `calabi-edge -config edge.yaml -fingerprint` 打印它。边缘节点用公开受信的证书时，
  改设 `CALABI_COORD_EDGE_TRUST=system`。换边缘节点证书时，同时更新这个指纹。
- 边缘节点直接写协调器的公钥：`coord_pubkey: <calabi-coord pubkey>`。
- 协调器告诉设备的中继（`CALABI_COORD_DERP_ADDR`），就是跑 `role: both` 或 `role: relay` 的那台边缘节点。

---

## 入网

在电脑上：

```bash
calabi join "calabi://join?…"
```

客户端的守护进程在运行时，由它入网并以你服务器的设备身份重新启动；没在运行时，入网信息存进客户端的数据目录，
再启动守护进程（`--no-start-daemon` 跳过这一步）。`--name` 设设备名；`--pin` 给不带指纹的邀请补上协调器的指纹；
`--replace` 把设备从一台服务器换到另一台。已登录 calabi.net 时，它会请你先 `calabi logout`。

装了 calabi 服务的电脑（桌面 App 装的，或 `calabi daemon install` 装的）上，那个服务是另一个客户端，有自己的数据目录：
这次入网到不了它，`calabi join` 也不启动任何东西。要用这次入网，运行 `calabi daemon`；要让服务连上你的服务器，在它自己的控制台里连接。

在客户端的控制台 `http://127.0.0.1:7400`（桌面 App 的窗口）里也一样：**连接自建服务器**，粘贴链接
（或手填协调器地址和密钥）。手机上：Calabi App → **连接自建服务器** → 扫邀请的二维码。

**证书。** 在密钥发出去之前，App 先定下怎么核对协调器：用邀请里的指纹、系统信任的证书，或者——两者都没有时——
显示协调器出示的指纹，让你和 `calabi-coord fingerprint` 的输出核对。密钥最后才花，所以停在这一步什么都没花掉。
边缘节点不需要这一步：它的指纹来自协调器。

**服务器和批量设备。** 需要自己入网的机器——一台服务器、同一个镜像装出来的一批机器——用配置文件代替邀请：

```yaml
# tunnels.yaml
mesh:
  coord: server.example.com:7012
  trust: pin
  pins: ["sha256:…"]          # calabi-coord fingerprint
  auth_key: ck_…              # calabi-coord authkey create --reusable --tag tag:server
  name: build-01
  # enabled: true             # 同时加入组网；隧道不受影响
tunnels: []
```

```bash
calabi daemon install --config tunnels.yaml    # 开机自启的服务；之后 calabi daemon start|stop|status
```

守护进程第一次用密钥入网，记住自己是哪台设备（数据目录里的 `mesh-reauth.json`），之后都靠证明自己的私钥回来。
`auth_key:` 按字面读取——把文件权限收紧。带注释的完整版见 [`docs/examples/tunnels.yaml`](examples/tunnels.yaml)。

---

## 隧道

`calabi http|tcp|udp|sni` 每条命令开一条隧道，挂在前台：

```bash
calabi http 8080                         # → https://u000001.tunnels.example.com
calabi http 8080 --domain app.tunnels.example.com
calabi tcp  22   --remote-port 20022
calabi udp  53
```

它们用这个客户端入网时的设备身份——边缘节点由协调器告诉、凭证由协调器签发——所以什么都不用设。没入网的客户端会直接说明。
`CALABI_DAEMON_CONFIG=tunnels.yaml` 让它们改用某个配置文件里那台设备的身份，而不是控制台的。

**设备怎么连上边缘节点。** 每次连接前，设备向协调器要边缘节点和一份新凭证，按协调器给的指纹钉住边缘节点的证书去连，
再用自己的私钥回应边缘节点的挑战。凭证有效一小时，剩三分之一时续期；凭证到期还没续上的会话会被边缘节点断开。
被停用或删除的设备就是这样失去隧道的。

**客户端会往外连什么。** 你服务器的设备只连你的协调器和它告诉的边缘节点，别的什么都不连。这份源码里没有任何统计上报，
整个客户端只有一个写死的非本地地址：`download.calabi.net` 上签名的更新清单，只有 calabi.net 版守护进程会去拉；
自建版守护进程在走到那段代码之前就分流走了。

### 按隧道的安全策略

每一种按隧道的访问控制都在这个二进制里，你的边缘节点全部执行：**IP 白名单/黑名单**（所有隧道类型），以及 HTTP 的
**Basic 认证**、**连接限速**、**请求头改写**和**登录认证**（Google / GitHub）。密码在离开你的机器之前就在**本地**
做 bcrypt 哈希：

```bash
calabi http 8080 --domain app.tunnels.example.com \
  --ip-allow 10.0.0.0/8 --ip-deny 1.2.3.4 \
  --basic-auth alice:s3cret --basic-auth bob:hunter2 \
  --security-file policy.json      # 或一整份 {"security":{…}}
```

边缘节点的回复会说明是否应用了这份策略，命令会把它打印出来。

### 守护进程

守护进程在一个进程里跑一台设备的所有隧道、自己重连，并提供控制台。`calabi join` 之后它就在运行；`calabi daemon` 启动它。
你在控制台里建的隧道存在它自己的 `tunnels.yaml`，在它的数据目录里。

用 `--config tunnels.yaml` 运行的守护进程，改从这个文件读隧道（以及要入网的服务器）；见[服务器和批量设备](#入网)
和 [`docs/examples/tunnels.yaml`](examples/tunnels.yaml)：

```yaml
tunnels:
  - name: app
    type: http
    local: 127.0.0.1:8080
    domain: app.tunnels.example.com
    security:
      ip_allow: ["10.0.0.0/8"]
      basic_auth: ["admin:s3cret"]   # 加载时 bcrypt
  - name: ssh
    type: tcp
    local: 127.0.0.1:22
    remote_port: 20022
```

> **服务说明。** `calabi daemon install --config …` 注册一个开机自启、崩溃后自动重启的服务（Windows 服务、systemd、launchd）。
> 服务没有用户主目录，所以日志写在 `calabi` 程序旁边。改 `--config` 要 `calabi daemon uninstall` 再 `install` 才生效。
> standalone 模式下不带 `--config` 的 `daemon install` 会拒绝：服务读的是它自己的数据目录，你 `calabi join` 的结果不在那里。
> 桌面 App 的服务则从它自己的控制台入网。

### 本地 Web 控制台（`:7400`）

守护进程运行时，**http://127.0.0.1:7400** 显示：

- 隧道和流量计数——并能新建、编辑、删除，安全策略也在这里改（改一条只重新注册那一条）；
- **请求检查器**（逐连接日志，HTTP 请求/响应抓取）；
- 守护进程日志；
- 服务器：协调器记下的所有设备的隧道、本月流量，以及**设置 → 自建服务器**：协调器、这台设备的隧道所在的边缘节点、组网开关。

一次性的 `calabi http 8080` 在同一端口（或下一个空闲端口）只提供一个简单的状态页。

如果把控制台绑到回环以外（`CALABI_STATUS_ADDR`），其他机器上的访问者要先输入解锁口令：守护进程启动时打印它，
存在数据目录的 `console-secret` 里，也可以用 `CALABI_STATUS_SECRET` 指定你自己的。它是明文 HTTP——在不信任的网络上，
用 SSH 隧道或 HTTPS 代理。

> 控制台的编辑会改写 `tunnels.yaml`（值保留，**注释不保留**——会加一行「由控制台管理」的文件头）。
> 如果你把手写的文件放在版本控制里，建议直接编辑它再重启守护进程。

---

## 组网

隧道把公网引进来。组网把**你自己的**机器连成一张私有 WireGuard 网络——`100.64.0.0/10` 里跟着机器走的固定地址，
NAT 允许时点对点直连，不允许时走边缘节点的中继。协调器看不到任何私钥或明文，中继也看不到。

入网的设备就在组网上。**关掉它**——控制台的**设置 → 自建服务器**，或 `calabi mesh down`（`calabi mesh up` 再打开）——
设备就离开组网：没有网卡，也不在其他设备那里出现。它仍然是入网状态，隧道照常；这个开关重启后依然保持。

组网需要 tun 设备和权限：以服务运行守护进程，或以 root / 管理员身份运行。Windows 上 `wintun.dll` 已经嵌在程序里。
设备的 WireGuard 私钥在本地生成并保留（`key_file:` 指定位置），所以设备的身份和地址不变。

守护进程 `tunnels.yaml` 里的组网设置写在 `coord:` 旁边——控制台改的就是这些：

```yaml
mesh:
  enabled: true
  coord: server.example.com:7012
  pins: ["sha256:…"]
  name: laptop
  advertise_routes: ["192.168.1.0/24"]   # 共享一个局域网
  advertise_exit_node: true              # 愿意当出口设备
  exit_node: home-server                 # 这台设备的流量经某台设备出去
```

`calabi mesh up --coord … --pin … --auth-key …` 不经守护进程、在前台单独跑组网——用来快速试一下；它和协调器的连接一断就退出。
`calabi mesh status` 查询运行中的守护进程。

### ACL

不设 `CALABI_COORD_POLICY_FILE` 时，同一个组网里每台设备都能访问其他所有设备。设了之后，一份写着分组和规则的 JSON 文件
决定谁能在哪些端口上访问谁。改动会热加载。协调器启动时文件有错，它会**失败即拒绝**（全部拒绝）并大声说明，而不是退回全放行；
修好文件就恢复，不用重启。运行中改坏的一次编辑会记日志，之前的策略继续生效。

经管理 API（`CALABI_COORD_MESH_ADMIN_ADDR` 上的 `PUT /admin/meshnets/<id>/acl`）为某个组网保存的 ACL，会替代文件
（或全放行）作用于该组网。管理 API 没有再删除它的调用；没有 `CALABI_COORD_DB_DSN` 时，它持续到协调器重启为止。

### 子网路由与出口设备

通告路由、愿意当出口设备，在所有平台上都能用。转发那一半——打开 IP 转发和 NAT，让包真的过去——**只在 Linux 上自动完成**；
其他平台上设备只负责通告，操作系统需要你自己配置。*使用*出口设备——把自己的默认路由经它出去——在 Linux、Windows、macOS 上都能用。

---

## 手机和桌面控制台

Android App 和客户端的控制台（`:7400`，桌面 App 的窗口）都从登录页连你的服务器：**连接自建服务器**——邀请链接或二维码，
或者协调器地址和密钥。手机加入组网，不提供隧道。控制台的守护进程会在原地、原端口以你服务器的设备身份重新启动。
用 `--config` 运行的守护进程保持它的文件指定的服务器；环境里设了 `CALABI_MODE` 的，或者用 API 密钥装的服务，都不会切换。

如果协调器后来出示了另一张证书，App 会停止连接它，并把它信任的指纹和现在出示的指纹并排显示。信任新的只对那一张证书有效。
在那之前 App 一直用原来的信任重试，所以把旧证书换回来，设备就会自己回来，不用谁去碰。边缘节点换证书则不需要任何人做什么：协调器会转告。

**设备、隧道、流量。** 两个 App 都列出组网里的设备。协调器有数据库时，也显示隧道和本月流量：

- 隧道是桌面守护进程上报的——名字、类型、公网地址、本地地址、是否在线、字节数——每五分钟一次，列表变化时立即上报，
  组网开着关着都一样。设备在组网上、或者持续在上报时，算作它的隧道在线。`calabi http` 开的隧道不在列表里。
- 本月流量是隧道流量加上经中继的组网流量，只在发送方计一次。设备之间的直连不经过你的服务器，不计。
  按天、按月跟随查看者所在的时区。协调器保留 92 天的隧道流量。
- 没有 `CALABI_COORD_DB_DSN` 时，隧道列表放在协调器内存里（重启后几分钟内守护进程会重新填满），也没有流量记录；
  App 会说明这一点，而不是显示零。

**离开。** 控制台里的*断开并忘记此服务器*、手机上的*离开此服务器*：协调器会被告知这台设备已离开，之后要新的邀请才能回来，
App 也会忘掉这台服务器。控制台还会删除它的 `tunnels.yaml`，隧道一起删除——会先告诉你有几条——然后回到 calabi.net 登录页。
设备私钥保留，所以再加入同一个协调器还是同一台设备。

---

## 自建拿不到什么

这些是控制面功能。命令在程序里，但需要 calabi.net 账号才有用：

- `calabi login / logout / org / certs / domains / clients`，
- 托管的多地域边缘节点和边缘节点发现，
- 账号、组织、计费，console.\<host\> 上的 Web 控制台，
- 为隧道域名自动申请 Let's Encrypt 证书。

注意这份清单里*没有*组网。`calabi-coord` 是完整的协调器，不是演示——自己的密钥、ACL、中继和设备。托管平台换掉的是
*信任谁的账号*以及计量；组网本身就是这份代码。反过来，自建服务器只属于你，不能指向托管平台的设备，平台用户也永远不需要自己跑一台。

---

## 上生产要注意的

- **备份协调器的状态**：数据库、`coord-grant.key` 和 `coord-tls/`。没有它们，每台设备都要用新邀请重新入网。
- 保留边缘节点的 `state.dir`：子域名计数器和它的证书都在里面。
- 管理端口（协调器的 `:9122` 和管理 API、边缘节点的 `:9101`）只放在内网接口上。
- 两边都设 `CALABI_ENV=production`：遇到失败即放行的默认值就拒绝启动。
- 边缘节点的全进程背压上限可以用环境变量设（`EDGE_GLOBAL_MAX_CONNS`、`EDGE_GLOBAL_ACCEPT_RATE_PER_SEC`）。
- 设备的守护进程装成服务（`calabi daemon install --config …`），开机就回来。

---

## 从 1.12 及更早版本升级

1.13 让协调器成为每台设备的身份，隧道和组网都是：

- **边缘节点的 token 表删除了。** 边缘节点现在需要 `mode: standalone` 和协调器的公钥，凭协调器的凭证接受设备。
  仍列着 `accepted_tokens` 的配置启动时会被拒绝。
- **`tunnels.yaml` 不再写边缘节点。** 顶层的 `server`、`token`、`token_env`、`insecure`、`ca_file`、`trust`、`pins`
  在你手写的文件里会被拒绝（控制台自己的文件里会被去掉并给出警告）。入网到协调器（`calabi join`，或 `mesh:` 块），
  边缘节点就从协调器来。
- **一次性命令**在 standalone 模式下不再读 `CALABI_SERVER`、`CALABI_TOKEN`、`CALABI_EDGE_PIN`、`CALABI_EDGE_TRUST`。
- **standalone 中继一律核对凭证。** 给它协调器的公钥。
- 没有证书文件的协调器以前提供明文；1.13 起提供自签证书。在设备上钉住它的指纹，或设 `CALABI_COORD_TLS=off`。
- `calabi mesh down` 现在会让自建设备在重启后也保持不在组网上；不带参数的 `calabi mesh up` 把它放回去。

---

## 许可证与贡献

按 [LICENSE](../LICENSE) 中的条款开源（另见 `NOTICE`）。欢迎对边缘节点核心、客户端核心、协调器和本地控制台提 issue 和补丁。

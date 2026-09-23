# Calabi —— 自建

[English](self-hosting.md) · **中文**

自建的 Calabi 服务器由两个程序组成，你的每台设备上跑客户端：

- `calabi-coord`，协调器——设备用邀请加入它，分到一个 `100.64.x.x` 地址。它保存设备列表、ACL 和邀请，
  并告诉每台设备边缘节点在哪。
- `calabi-edge`，边缘节点——为你的**隧道**接公网流量；设备之间无法直连时，为**组网**中继流量。
- `calabi`，客户端——运行隧道，加入私有 WireGuard 组网。

设备入网一次，之后隧道和组网都能用。组网可以在某台设备上单独关掉，它的隧道照常运行。

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

自建服务器不需要账号，也不连我们的任何服务。Android App（`apps/client-android`）和客户端的控制台也能加入它，
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

- [只在 calabi.net 上有的](#只在-calabinet-上有的)
- [上生产要注意的](#上生产要注意的)
- [升级到 2.0](#升级到-20)
- [从 1.12 及更早版本升级](#从-112-及更早版本升级)
- [常见问题](#常见问题)
- [许可证与贡献](#许可证与贡献)

---

## 用 Docker 快速起一台服务器

在一台有公网地址、装了 Docker Compose（或 `podman compose`）的 Linux 机器上，[`deploy/server`](../deploy/server)
用一份 `.env` 把协调器和边缘节点一起跑起来：

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

在手机上，用 Calabi App 扫邀请的二维码。

捆绑包的设备管理、升级和备份，见它的 [README](../deploy/server/README.md)。本页其余部分逐个介绍各部分和每一项设置。

---

## 获取程序

[发布页](https://github.com/calabinet/calabi/releases)有这三个程序的 Linux（amd64、arm64、armv7）、macOS（amd64、arm64）
和 Windows（amd64、arm64）版，附带一份 `build-manifest.json`，用来从这份源码重新构建。也有 Docker 镜像（amd64、arm64）：
`calabinet/calabi-coord`、`calabinet/calabi-edge`、`calabinet/calabi`。

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

协调器、边缘节点和设备用同一个版本。设备要 1.13 或更新才能入网。

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
| `CALABI_COORD_PUBLIC_ADDR` | 设备拨的地址，`host:port`。邀请链接里带的就是它 |
| `CALABI_COORD_DB_DSN` | 状态存在哪：`sqlite:./coord.db`，或一个 `postgres://…`。不设 = 放内存（见下） |
| `CALABI_COORD_MESH_ADMIN_ADDR` / `_TOKEN` | 管理 API，`calabi-coord invite`、`authkey`、`device` 都用它。只放在内网地址上。令牌必填 |
| `CALABI_COORD_ADMIN_ADDR` | 健康检查和指标。默认 `:9122`，不要对外 |
| `CALABI_COORD_EDGE_ADDR` | 设备开隧道用的边缘节点：它控制端口的 `host:port` |
| `CALABI_COORD_EDGE_PIN` | 边缘节点的证书指纹（`calabi-edge -fingerprint`）。不设 = 协调器自己去边缘节点读（[怎么读](#设备怎么信任边缘节点的证书)） |
| `CALABI_COORD_EDGE_TRUST` | `system`：边缘节点用的是公开受信的证书，设备按系统根证书核对 |
| `CALABI_COORD_EDGE_PROBE_ADDR` | 协调器连边缘节点读证书用的地址，和 `EDGE_ADDR` 不同时才设（同机是 `127.0.0.1:7443`，compose 网络里是 `edge:7443`） |
| `CALABI_COORD_RELAY_GRANT_KEY_FILE` | 协调器给设备签[凭证](#凭证是什么)用的密钥。默认 `./coord-grant.key`，首次启动时生成 |
| `CALABI_COORD_GRANT_PUBKEY_FILE` | 每次启动把这把密钥的公钥写到这个文件，给边缘节点读 |
| `CALABI_COORD_DERP_ADDR` | 一台中继，`host:port` |
| `CALABI_COORD_DERP_STUN_PORT` | 这台中继的 STUN 端口。设备靠 STUN 测量来选中继，所以要设 |
| `CALABI_COORD_DERP_HOME_REGION` | `CALABI_COORD_DERP_ADDR` 这个区域的名字（默认 `default`）；用了映射文件而文件没写 `home_region` 时，是新设备起步的区域 |
| `CALABI_COORD_DERP_MAP_FILE` | 多台中继：一个 JSON 文件（见 `apps/calabi-coord/examples/derp-map.example.json`） |
| `CALABI_COORD_AUTHKEYS_FILE` | 你自己的永久密钥，可选。JSON：`{"key": {"meshnet": 1, "tags": ["tag:laptop"]}}` |
| `CALABI_COORD_POLICY_FILE` | [ACL](#acl) 文件。不设 = 同一个组网里每台设备都能访问其他所有设备 |
| `CALABI_COORD_NODE_QUOTA` | 每个组网最多多少台设备。不设或 `0` = 不限 |
| `CALABI_COORD_TLS_CERT_FILE` / `_KEY_FILE` | 你自己的证书，要么都设、要么都不设。都不设 = 自签证书（见[它的证书](#协调器的证书)） |
| `CALABI_COORD_TLS_DIR` | 自签证书放在哪。默认 `./coord-tls` |
| `CALABI_COORD_TLS` | `off` 表示明文 |

**数据库。** 设 `CALABI_COORD_DB_DSN`，`sqlite:./coord.db` 就够。不设时，设备、ACL、服务和中继都放在内存里：
一重启，每台设备都要重新入网，还会分到新地址。设了但用不了的 DSN 会让协调器启动失败。

**要保管的文件。** `coord-grant.key`、`coord-tls/` 目录和数据库。换了 `coord-grant.key`，边缘节点在拿到新公钥之前
会拒绝所有设备（`calabi-coord pubkey` 打印公钥）。

**组网编号。** 每把密钥属于一个组网（meshnet），用一个数字表示。不同组网里的设备，是同一个协调器上互相隔离的网络。

**先试一下。** 既没有密钥文件也没有数据库时，协调器接受内置密钥 `dev-meshnet-1-key`，放进组网 1。

**`CALABI_ENV=production`。** 公网能访问到的协调器要设它。设了之后，遇到放行的默认值就拒绝启动：需要密钥文件或数据库
（内置密钥不再可用），并且要设 `CALABI_COORD_NODE_QUOTA`（`0` 表示不限）。

### 协调器的证书

协调器提供 TLS。没有 `CALABI_COORD_TLS_CERT_FILE`/`_KEY_FILE` 时，它首次启动生成一张自签证书，放在
`CALABI_COORD_TLS_DIR`。`calabi-coord fingerprint` 打印它的指纹，邀请里也带着。保留这个目录：换了证书，
每台设备都要重新确认。

设备怎么核对协调器的证书（配置里的 `trust:`，`calabi mesh up` 的 `--trust`）：

| trust | 核对什么 | 怎么设 |
|---|---|---|
| `pin` | 证书的公钥是否等于某个指纹；不核对主机名 | 邀请里的指纹、`pins:`、`--pin` |
| `system` | 操作系统信任的根证书和主机名——适合 Let's Encrypt 或其他公开 CA 签的证书 | 邀请没带指纹时的默认 |
| `ca` | 只信你的 CA，并核对主机名 | `ca_file:`、`--ca-file` |
| `plaintext` | 什么都不核对 | `trust: plaintext`、`--trust plaintext` |

`CALABI_COORD_TLS=off` 表示明文，用于你信任的网络，或前面有代理终止 TLS。这种协调器的邀请要用
`calabi-coord invite --allow-plaintext` 生成；在 App 里手填它的地址，要勾上**不加密**。

---

## 边缘节点

边缘节点读一个 YAML 文件（`./calabi-edge -config edge.yaml`）：

```yaml
# --- 这台节点：是谁、归谁管、跑什么 ---
mode: standalone             # 属于你自己的协调器；必填
role: both                   # tunnel | mesh | both
coord_pubkey_file: ./coord.pub   # 协调器的凭证公钥（或 coord_pubkey: <base64>）
node_label: my-server        # 这个节点在日志里的名字

admin:
  addr: "127.0.0.1:9101"     # /healthz + /metrics——不要对外
state:
  dir: ./state               # 子域名计数器和自签证书

# --- 只有隧道服务读这一段 ---
tunnel:
  base_domain: tunnels.example.com  # HTTP 隧道成为 <名字>.<base_domain>
  control_port: 7443         # calabi 客户端连这里
  control_cert_pem: ""       # 证书；留空 = 自签，放在 state.dir
  control_key_pem: ""
  http_port: 80              # 访问者
  https_port: 443            # 见下面的 HTTPS

# --- 只有组网中继读这一段 ---
mesh:
  derp_port: 3340            # 中继
  stun_port: 3478            # 0 关掉 STUN
  label: my-server           # 这台中继在日志里的名字
```

`role: mesh` 的节点可以把整个 `tunnel:` 段删掉，`role: tunnel` 的可以把整个 `mesh:` 段删掉。
这就是分成两段的意义：文件本身说清楚了这台机器跑的是哪一半。

- **`mode: standalone`**——必填。边缘节点凭你的协调器签的凭证接受设备，执行每条隧道的安全策略，并允许客户端在
  `base_domain` 下自己选名字。
- **`coord_pubkey` / `coord_pubkey_file`**——必填。协调器的凭证公钥：直接写（`calabi-coord pubkey` 打印它），
  或者写协调器导出的那个文件。文件还不存在时，边缘节点会等它出现。也可以用环境变量
  `CALABI_EDGE_COORD_PUBKEY` / `CALABI_EDGE_COORD_PUBKEY_FILE`。
- **证书。** 没有 `tunnel.control_cert_pem`/`control_key_pem` 时，边缘节点首次启动生成一张自签证书，放在 `state.dir`
  （`control.crt`、`control.key`）。`./calabi-edge -config edge.yaml -fingerprint` 打印它的指纹。
  客户端从协调器拿到这个指纹。没有 `state.dir` 时，每次启动都换一张新证书，并给出警告。
- **TCP 和 UDP 隧道**的公网端口从 20000–20999 里分配，或者用客户端指定的端口（`--remote-port`、`remote_port:`）。
  那个端口也要开放。
- **热加载。** `tunnel.base_domain` 可以在运行中改（编辑文件即可）。其他字段改了要重启；运行中改它们，这次重载会被拒绝并记日志。
- **一个地址，每个服务各自的端口。** `public.host` 说这个节点在外面怎么被找到，端口由监听它的那个服务命名。
  客户端拨的地址是两者拼出来的，所以没有任何端口写两遍。
- **有两个来源的设置**会互相核对，文件里两处答案不一致就拒绝启动，并把两个都点名：接了控制面的节点，
  `region` 和 `edge_node_id` 对这个节点自己的证书——控制面就是从那里读的。
- **旧写法**，升级上来的话要知道。挪过位置的设置全都还能从原来的地方读：监听器的 `control:`、`http:`、
  `https:`、`sni:` 四段等同于 `control_port`、`http_port`、`https_port`、`sni_port` 四个端口，
  `public.addr` 等同 `public.host`（里面的端口必须和控制监听器一致），`base_domain` 和
  `coord_pubkey` 可以在 `http:`、`relay:` 底下，`node_id` 等同 `node_label`，整个 `relay:` 段等同 `mesh:`。
  角色名 `edge`、`relay` 仍然分别表示 `tunnel`、`mesh`。同一个设置两种写法都写了且值不同，会被拒绝并告诉你该留哪个。
  `accepted_tokens` 在 1.13 删除了：空列表会被忽略，列着 token 的会被拒绝。

### 全部设置

三组：两个服务都用的、只有隧道用的、只有组网中继用的。`role: mesh` 的节点可以整段不写 `tunnel:`，
`role: tunnel` 的可以整段不写 `mesh:`。

**适用**这一列说明这项是给谁的。标 **calabi.net** 的是托管服务用的，自建服务器一项都不读，
那些行可以整行跳过。其余的要么任何节点都适用，要么只对你自己的服务器有意义。

**这台节点——两个服务都读，或者都不读**

| 设置 | 适用 | 默认 | 作用 |
|---|---|---|---|
| `node_label` | 任何节点 | `edge-dev-1` | 这个节点给人看的名字（`lax-1`、`sgp-01`）。它会到达你的客户端、日志和每一条用量记录 |
| `region` | 任何节点 | `local` | 这个节点在哪个区域。中继的区域码也从它来，`self-<region>` |
| `mode` | 任何节点 | `platform` | 每条隧道的安全策略信谁的：`standalone`（你自己的服务器）信客户端的，`platform` 信控制面的 |
| `role` | 任何节点 | `tunnel` | 这台节点提供两种服务里的哪种：`tunnel`、`mesh` 或 `both` |
| `coord_pubkey` | 任何节点 | — | 你的协调器的凭证公钥，base64。`calabi-coord pubkey` 打印它 |
| `coord_pubkey_file` | 任何节点 | — | 同一把公钥，改成读文件。边缘节点会等它出现 |
| `public.host` | 任何节点 | — | 这个节点在外面怎么被找到，写主机名或 IP、不带端口——客户端从这里连它的隧道，设备从这里连它的中继。**服务隧道的节点必填** |
| `admin.addr` | 任何节点 | `:9101` | `/healthz`、`/readyz`、`/metrics`。不要放到公网上 |
| `state.dir` | 任何节点 | — | 重启后还要在的小东西：子域名计数器和自签证书 |
| `multi_region.*` | calabi.net | `mode: cluster` | 托管平台连控制面用的：`mode: bff-edge`、`bff_edge_addr`、`client_cert`、`client_key`、`ca`、`server_name` |
| `log.level` / `log.format` | 任何节点 | `info` / `text` | `debug`/`info`/`warn`/`error`，以及 `text`/`json` |

**`tunnel:`——只有隧道服务读**

| 设置 | 适用 | 默认 | 作用 |
|---|---|---|---|
| `base_domain` | 任何节点 | `localtest.me` | 这个节点服务的泛域名：隧道成为 `<名字>.<base_domain>` |
| `control_port` | 任何节点 | `7443` | `calabi` 客户端连到哪里 |
| `control_cert_pem` / `control_key_pem` | 任何节点 | — | 这个监听器的证书。不写的话边缘节点自签一张，放在 `state.dir`。文件变化时会重读 |
| `http_port` | 任何节点 | `8080` | HTTP 隧道的访问者 |
| `https_port` | 任何节点 | `8443` | HTTPS 隧道的访问者，TLS 在这里终止。写 `0` 关掉 HTTPS |
| `https_self_signed` | 你的服务器 | `false` | 没有真证书时回落到自签证书。**只给开发用** |
| `sni_port` | 任何节点 | — | TLS 原样透传给客户端，不在这里解密。不写就关掉 |
| `peer_forward.forward_addr` | calabi.net | — | 这台在哪里接收邻居转发来的访客流量。**是内网地址，绝不能用公网的那个** |
| `peer_forward.advertise_addr` | calabi.net | — | 邻居拨过来用的内网 `host:port`。两个都要设 |

**`mesh:`——只有组网中继读**

| 设置 | 适用 | 默认 | 作用 |
|---|---|---|---|
| `derp_port` | 任何节点 | `3340` | 设备从哪里连到中继 |
| `stun_port` | 任何节点 | `3478` | 设备用来挑最近中继的 STUN 应答口。`0` 关掉它 |
| `label` | 任何节点 | 节点的 `region` | 这台中继广播的区域名，形式是 `self-<label>`。一个区域里放了两台中继时才设 |
| `kind` | 任何节点 | `self` | `self` 是你自己的中继，`platform` 是我们的 |
| `require_auth` | 任何节点 | `false` | 拒绝没有有效凭证的设备。`standalone` 节点上永远是开的 |

**会被拒绝的设置。** 边缘节点不再直连控制面，所以 `identity:`、`quota:`、`config_svc:`、`nats:`、
`tunnel.addr` 和 `cert.addr` 都不起作用了。`presence.interval_seconds` 和 `cert.refresh_seconds` 也一样，
2.0.0 删了：两个都有默认值，而且没有任何一份已部署的配置设过它们。`edge_class` 同理——
现在由托管平台自己决定，节点没有权力挑选哪些付费套餐被路由到它这里。`org_id`（以及旧写法 `cert.org_id`）
也一样：节点属于哪个组织由它自己的证书决定，而我们自己的节点服务所有组织、不指定其中某一个。
文件里还留着其中任何一个，边缘节点不会启动，并告诉你是哪一个——而不是启动起来、然后悄悄不做文件里写的事。
唯一一个不被读取而是被拒绝的旧写法，是顶层带 `forward_addr` / `advertise_addr` 的 `mesh:` 段：
那是边缘之间转发隧道流量，而 `mesh:` 现在配置的是中继，把两者中任何一个读成另一个都比直说更糟。

**用环境变量**，让一台中继完全不需要配置文件：`CALABI_EDGE_MODE`、`CALABI_EDGE_ROLE`、
`CALABI_EDGE_ADMIN_ADDR`、`CALABI_EDGE_PUBLIC_HOST`、`CALABI_EDGE_COORD_PUBKEY`、`CALABI_EDGE_COORD_PUBKEY_FILE`，
以及 `CALABI_EDGE_RELAY_` 加 `KIND`、`LABEL`、`DERP_PORT`、`STUN_PORT`、`REQUIRE_AUTH`、`COORD_PUBKEY`。

### HTTPS

设了 `base_domain`、又没有自己的证书时，边缘节点在 `tunnel.https_port` 上用它在 `state.dir` 里生成的自签泛域名证书
（`edge-https.crt`）提供 HTTPS。浏览器会显示警告，除非你导入这张证书。自建边缘节点暂时不能自动申请 Let's Encrypt 证书。

### 单独一台中继

要在别处加一台中继（离你某些设备更近），用 `role: mesh` 运行边缘节点，不需要配置文件：

```bash
CALABI_EDGE_MODE=standalone CALABI_EDGE_ROLE=mesh \
CALABI_EDGE_RELAY_LABEL=tokyo CALABI_EDGE_COORD_PUBKEY=<calabi-coord pubkey> \
./calabi-edge
```

它监听 3340/tcp 和 3478/udp，只为持有你协调器凭证的设备服务。把它写进协调器的 `CALABI_COORD_DERP_MAP_FILE`，
或经管理 API 登记。每台设备测量各台中继，选最近的一台。

---

## 邀请和设备

管理命令连运行中的协调器，用同样的环境变量（或 `--admin`、`--token`）：

```bash
./calabi-coord invite --note "小明的手机"
```

它打印一条 `calabi://join?…` 链接、一个二维码，以及等价的 `calabi join "…"` 命令行。

- 默认一份邀请**只放进一台设备**，**24 小时内**有效。`--uses 5`、`--reusable`、`--expires 72h`、`--no-expiry` 可以改。
- `--tag tag:phone` 给它放进的每台设备打上这个 ACL 标签。
- 链接里带着密钥；协调器用自签证书时，还带着它的指纹。只发给要用它的人。

```bash
./calabi-coord authkey create --reusable --no-expiry --tag tag:server   # 只要密钥、不要链接
./calabi-coord authkey list
./calabi-coord authkey revoke 3            # 不再让新设备用它入网

./calabi-coord device list
./calabi-coord device disable 5            # ID 那一列；`enable 5` 恢复
./calabi-coord device delete 5
./calabi-coord device approve 5            # 组网要求审批时
```

- **要移除设备，就停用或删除它。** 它立刻离开组网，隧道在一小时内停止（[为什么](#凭证是什么)）。删除的设备要新的邀请才能回来。
- **吊销密钥**只是不让新设备再用它入网，已经放进来的设备不受影响（[为什么](#为什么吊销密钥不会移除它放进来的设备)）。
- 协调器只存每把密钥的哈希，所以密钥只在生成时显示一次。

---

## 协调器和边缘节点分开部署

- **协调器上：** `CALABI_COORD_EDGE_ADDR`（边缘节点的公网地址），以及 `CALABI_COORD_EDGE_PIN`（在边缘节点上运行
  `calabi-edge -config edge.yaml -fingerprint` 得到）。边缘节点用公开受信的证书时，改设 `CALABI_COORD_EDGE_TRUST=system`。
  换边缘节点证书时，同时更新这个指纹。
- **边缘节点上：** 直接写协调器的公钥：`coord_pubkey: <calabi-coord pubkey 的输出>`。
- **中继：** 协调器告诉设备的中继（`CALABI_COORD_DERP_ADDR`），是跑 `role: both` 或 `role: mesh` 的边缘节点。

---

## 入网

在电脑上：

```bash
calabi join "calabi://join?…"
```

- 客户端的守护进程在运行时，由它入网，并以你服务器的设备身份重新启动。没在运行时，入网信息先保存下来，再启动守护进程
  （`--no-start-daemon` 不启动）。
- `--name` 设设备名；`--pin` 给不带指纹的邀请补上协调器的指纹；`--replace` 把设备从另一台服务器换到这一台。
- 已登录 calabi.net 时，它会请你先退出（`calabi logout`）。
- 装了 calabi 服务的电脑上（桌面 App 装的，或 `calabi daemon install` 装的），`calabi join` 到不了这个服务，也不启动任何东西。
  要用这次入网，运行 `calabi daemon`；要让服务连上你的服务器，在它自己的控制台里连接
  （[为什么](#为什么-calabi-join-到不了已安装的服务)）。

在客户端的控制台 `http://127.0.0.1:7400`（桌面 App 的窗口）里：**连接自建服务器**，粘贴链接，或手填协调器地址和密钥。
手机上：Calabi App → **连接自建服务器** → 扫邀请的二维码。

**协调器的证书**在发送密钥之前核对：用邀请里的指纹、用系统信任的根证书，或者——两者都不适用时——显示指纹，让你和
`calabi-coord fingerprint` 的输出核对。停在这一步的入网不会用掉邀请。

**服务器和批量设备。** 需要自己入网的机器——一台服务器，或同一个镜像装出来的一批机器——用配置文件代替邀请：

```yaml
# calabi.yaml
server:
  coord: server.example.com:7012
  trust: pin
  pins: ["sha256:…"]          # calabi-coord fingerprint
  auth_key: ck_…              # calabi-coord authkey create --reusable --tag tag:server
  name: build-01
# mesh:
#   enabled: true             # 同时加入组网；隧道不受影响
tunnels: []
```

```bash
calabi daemon install --config calabi.yaml    # 开机自启的服务；之后 calabi daemon start|stop|status
```

密钥只在第一次入网时用。之后守护进程用设备私钥重连；它把自己是哪台设备记在数据目录的 `mesh-reauth.json` 里。
这个文件以明文保存密钥，请设成只有服务能读。带注释的示例见 [`docs/examples/calabi.yaml`](examples/calabi.yaml)。

---

## 隧道

`calabi http|tcp|udp|sni` 每条命令开一条隧道，挂在前台：

```bash
calabi http 8080                         # → https://u000001.tunnels.example.com
calabi http 8080 --domain app.tunnels.example.com
calabi tcp  22   --remote-port 20022
calabi udp  53
```

它们以这个客户端入网时的设备身份运行，不用再设别的。没入网的客户端会直接说明。
`CALABI_DAEMON_CONFIG=calabi.yaml` 让它们改用某个配置文件里那台设备的身份。

### 按隧道的安全策略

你的边缘节点执行每条隧道的访问控制：

- **IP 白名单和黑名单**，所有隧道类型都能用；
- HTTP 隧道还有：**Basic 认证**、**连接限速**、**请求头改写**、**登录认证**（Google、GitHub）。

```bash
calabi http 8080 --domain app.tunnels.example.com \
  --ip-allow 10.0.0.0/8 --ip-deny 1.2.3.4 \
  --basic-auth alice:s3cret --basic-auth bob:hunter2 \
  --security-file policy.json      # 或一整份 {"security":{…}}
```

Basic 认证的密码在你的机器上做 bcrypt 哈希后才发出去。命令会打印边缘节点是否应用了这份策略。

### 守护进程

守护进程在一个进程里跑一台设备的所有隧道、自己重连，并提供控制台。`calabi join` 之后它就在运行；`calabi daemon` 启动它。
你在控制台里建的隧道存在它自己的 `calabi.yaml`，在它的数据目录里。

用 `--config calabi.yaml` 运行时，它改从这个文件读隧道（以及要入网的服务器），见[服务器和批量设备](#入网)
和 [`docs/examples/calabi.yaml`](examples/calabi.yaml)：

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

**装成服务。** `calabi daemon install --config …` 注册一个开机自启、崩溃后自动重启的服务（Windows 服务、systemd、launchd）。

- 服务的日志写在 `calabi` 程序旁边。
- 要改 `--config`，先 `calabi daemon uninstall`，再重新 `install`。
- 自建的设备上，`daemon install` 必须带 `--config`。桌面 App 的服务从它自己的控制台入网。

### 本地 Web 控制台（`:7400`）

守护进程运行时，**http://127.0.0.1:7400** 显示：

- 隧道和流量，并能新建、编辑、删除，安全策略也在这里改（改一条只重新注册那一条）；
- **请求检查器**（逐连接日志，HTTP 请求和响应）；
- 守护进程日志；
- 你的服务器：所有设备的隧道、本月流量，以及**设置 → 自建服务器**——协调器、这台设备的隧道所在的边缘节点、组网开关。

一次性的 `calabi http 8080` 只提供一个简单的状态页，在同一端口或下一个空闲端口上。

**从其他机器访问。** 用 `CALABI_STATUS_ADDR` 把控制台绑到回环以外。之后访问者要先输入解锁口令：守护进程启动时打印它，
存在数据目录的 `console-secret` 里，也可以用 `CALABI_STATUS_SECRET` 指定你自己的。控制台是明文 HTTP；
在不信任的网络上，放在 SSH 隧道或 HTTPS 代理后面。

**手写 `calabi.yaml`。** 控制台的编辑会改写这个文件：值保留，注释不保留，还会加一行「由控制台管理」的文件头。
放在版本控制里的文件，请直接编辑它再重启守护进程。

---

## 组网

组网把你的设备连成一张私有 WireGuard 网络。每台设备拿到一个 `100.64.0.0/10` 里的固定地址，换网络也不变。
NAT 允许时设备之间直连，不允许时经边缘节点的中继。

**开和关。** 入网的设备就在组网上。在控制台（**设置 → 自建服务器**）里关掉，或者运行 `calabi mesh down`；
`calabi mesh up` 再打开。关掉后，设备没有组网网卡，其他设备也看不到它。它仍然是入网状态，隧道照常运行，这个开关重启后依然保持。

**运行条件。** 以服务运行守护进程，或以 root / 管理员身份运行：组网要创建一块网卡。Windows 上 `wintun.dll` 已经内置在程序里。
设备的 WireGuard 私钥在设备上生成并保存（`key_file:` 指定位置），所以设备的身份和地址不变。

守护进程 `calabi.yaml` 里的组网设置——控制台改的也是这些。
设备归哪台服务器管在 `server:` 里，不在这一段：组网开不开，设备都需要它。

```yaml
server:
  coord: server.example.com:7012
  pins: ["sha256:…"]
  name: laptop
mesh:
  enabled: true
  advertise_routes: ["192.168.1.0/24"]   # 共享一个局域网
  advertise_exit_node: true              # 愿意当出口设备
  exit_node: home-server                 # 这台设备的流量经某台设备出去
```

`calabi mesh up --coord … --pin … --auth-key …` 只跑组网，挂在前台，不经守护进程——用来快速试一下。
它和协调器的连接一断就退出。`calabi mesh status` 查询运行中的守护进程。

### ACL

不设 `CALABI_COORD_POLICY_FILE` 时，同一个组网里每台设备都能访问其他所有设备。设了之后，一份写着分组和规则的 JSON 文件
决定谁能在哪些端口上访问谁。

- 文件改了，协调器会重新加载。
- 协调器启动时文件有错，就拒绝所有流量，并在日志里说明原因。修好文件即可，不用重启。
- 运行中改坏的一次编辑会记日志，原来的策略继续生效。

经管理 API（`CALABI_COORD_MESH_ADMIN_ADDR` 上的 `PUT /admin/meshnets/<id>/acl`）为某个组网保存的 ACL，会替代文件
（或全放行）作用于该组网。没有删除它的接口。没有数据库时，它持续到协调器重启为止。

### 子网路由与出口设备

**子网路由**把它背后的局域网共享给组网。**出口设备**替别的设备转发上网流量。

| | Linux | Windows、macOS |
|---|---|---|
| 共享子网，或当出口设备 | 可以——转发和 NAT 自动配好 | 只能在 `calabi.yaml` 里设（`advertise_routes:`、`advertise_exit_node:`），转发和 NAT 要自己配；控制台里不提供 |
| 访问别的设备共享的子网 | 可以 | 可以 |
| 使用出口设备 | 可以 | 可以 |

---

## 手机和桌面控制台

**连接。** 在 Android App 或客户端控制台（`:7400`，桌面 App 的窗口）的登录页上：**连接自建服务器**，
然后用邀请（链接或二维码），或者协调器地址和密钥。

- 手机加入组网，不运行隧道。
- 控制台的守护进程会以你服务器的设备身份重新启动，端口不变。
- 这些不会切换：用 `--config` 运行的守护进程（保持它的文件指定的服务器）、环境里设了 `CALABI_MODE` 的守护进程、用 API 密钥装的服务。

**协调器的证书变了时**，App 停止连接它，并把它信任的指纹和现在出示的指纹并排显示。信任新的就能重连，只对这一张证书有效。
在那之前 App 一直用原来的指纹重试，所以把旧证书换回来，设备会自己回来。边缘节点换证书不需要任何人操作。

**设备、隧道和流量。** 两个 App 都列出组网里的设备。协调器有数据库时，还显示隧道和本月流量：

- **隧道**——桌面守护进程上报的隧道：名字、类型、公网地址、本地地址、是否在线、字节数。守护进程每五分钟上报一次，
  列表变化时立即上报，组网开着关着都一样。`calabi http` 开的隧道不在列表里。
- **流量**——隧道流量加上经中继的组网流量（[怎么计算](#流量怎么计算)）。按天、按月跟随查看者的时区。
  协调器保留 92 天的隧道流量。
- **没有数据库时**，隧道列表放在内存里（重启后几分钟内守护进程会重新上报），也没有流量记录。App 会说明这一点。

**离开。** 控制台里的*断开并忘记此服务器*、手机上的*离开此服务器*：

- 协调器把设备标记为已离开，要新的邀请才能回来。
- App 忘掉这台服务器。
- 控制台还会删除它的 `calabi.yaml` 和里面的隧道（先告诉你有几条），然后回到 calabi.net 登录页。
- 设备私钥保留：再加入同一个协调器，还是同一台设备。

---

## 只在 calabi.net 上有的

这些需要 calabi.net 账号。客户端里有这些命令，但连自建服务器时用不了：

- `calabi login`、`logout`、`org`、`certs`、`domains`、`clients`；
- 托管在多个地域的边缘节点，以及在它们之间选择；
- 账号、组织、计费，以及网页控制台；
- 为隧道域名自动申请 Let's Encrypt 证书。

---

## 上生产要注意的

- **备份协调器**：数据库、`coord-grant.key` 和 `coord-tls/`。没有它们，每台设备都要用新邀请重新入网。
- 保留边缘节点的 `state.dir`：子域名计数器和它的证书都在里面。
- 管理地址只放在内网接口上：协调器的 `:9122` 和组网管理 API、边缘节点的 `:9101`。
- 协调器和边缘节点都设 `CALABI_ENV=production`，遇到放行的默认值就拒绝启动。
- 用 `EDGE_GLOBAL_MAX_CONNS` 和 `EDGE_GLOBAL_ACCEPT_RATE_PER_SEC` 限制边缘节点的总连接数。
- 设备的守护进程装成服务（`calabi daemon install --config …`），开机自动启动。

---

## 监控

协调器和边缘节点各自在管理地址上提供 `/metrics` 和 `/healthz`——这套部署里分别是 `:9122` 和 `:9101`，
都绑在 `127.0.0.1`。

[`deploy/server/monitoring`](../deploy/server/monitoring) 是配好的 Prometheus：抓取配置、三条告警，
以及证明这些告警会触发的测试。在 `deploy/server` 目录下：

```bash
docker compose -f docker-compose.yml -f monitoring/docker-compose.monitoring.yml up -d
ssh -L 9090:127.0.0.1:9090 you@your-server   # 然后打开 http://127.0.0.1:9090
```

三条告警：

| 告警 | 什么时候触发 |
| --- | --- |
| `CalabiTargetDown` | 两个程序之一连续 3 分钟没有应答。 |
| `CalabiEdgeFailingVisitors` | 边缘节点连续 10 分钟在丢弃或失败访客请求。 |
| `CalabiCoordRPCErrors` | 协调器连续 10 分钟在失败设备的 RPC。 |

你自己配的访问规则拦掉访客、陌生人扫描你的地址，这两类都不会触发告警——它们都是正常的
（[为什么](#为什么边缘节点那条告警不统计所有失败的请求)）。隧道背后的服务挂掉默认也不算，
[README](../deploy/server/monitoring/README.md) 里写了怎么把它加进来。

这套东西不连 calabi.net 的任何地方。

---

## 升级到 2.0

2.0 改了 edge 的配置文件。一台从 1.14 一直跑着的服务器，配置不跟着改，新版 edge
不会启动。

**用 Docker 发布包的**：换镜像的同时把新的 `docker-compose.yml` 一起换掉。edge
的配置是这个文件写出来的，而 2.0 之前那版写出来的配置新版 edge 会拒绝——它没有
`public:` 块。`.env` 不用加东西，值取自你本来就设了的 `CALABI_PUBLIC_HOST`。

**自己写 edge 配置的**：有两处会让它起不来。

- **跑隧道的节点 `public.host` 必填**。它是设备拨的那个主机名，也是控制证书签给
  的那个名字。以前它可以不写、回落到监听器的绑定地址——那个地址只在「设备就是本
  机」时才拨得通。只做中继的节点不需要它。
- **早就不起作用的设置改成拒绝**，不再是跳过：`identity:`、`quota:`、
  `config_svc:`、`nats:` 四个块，以及 `tunnel.addr`、`cert.addr`、
  `presence.interval_seconds`、`cert.refresh_seconds`、`edge_class`、`org_id`。
  删掉即可，edge 启动时会点名是哪一行。

其余都会自动迁移。文件现在按服务分层——`tunnel:` 放只有隧道读的，`mesh:`（原
`relay:`）放中继读的，两个都读的留在顶层——每个监听器写端口而不是地址，但所有旧
写法都还从原位加载：

| 你写的 | 现在读作 |
|---|---|
| `control: { addr: ":7443" }` | `tunnel.control_port: 7443` |
| `control: { cert_pem: … }` | `tunnel.control_cert_pem: …` |
| `http: { addr: ":80" }` | `tunnel.http_port: 80` |
| `https: { self_signed: true }` | `tunnel.https_self_signed: true` |
| `http: { base_domain: … }` | `tunnel.base_domain: …` |
| `relay:` | `mesh:` |
| `public: { addr: "host:7443" }` | `public: { host: "host" }` |

「自动迁移」有两个例外。`public.addr` 里的端口和控制监听器对不上的，会被拒绝并
同时点名两处——那种文件起来了也没人拨得通。还有顶层写成 `mesh:` 的
`peer_forward:` 块（edge 之间转发隧道流量，跟组网无关），不会被当成中继配置读，
而是直接拒绝；它现在叫 `tunnel.peer_forward:`。

客户端自己的配置文件这一版从 `tunnels.yaml` 改名为 `calabi.yaml`，协调器也从
`mesh:` 提到顶层的 `server:`。这一处你不用管：旧文件照常加载，下次有任何东西保存
它时会自动写成新格式。

---

## 从 1.12 及更早版本升级

1.13 起，协调器是每台设备的身份，隧道和组网都是。

- **边缘节点不再用 token。** 它需要 `mode: standalone` 和协调器的公钥，凭协调器的凭证接受设备。
  仍列着 `accepted_tokens` 的配置启动时会被拒绝。
- **守护进程配置不再写边缘节点。** 顶层的 `server: <url>`、`token`、`token_env`、`insecure`、`ca_file`、`trust`、`pins`
  在你手写的文件里会被拒绝，控制台自己的文件里会被去掉并给出警告。入网到协调器（`calabi join`，或 `server:` 块），
  边缘节点就从协调器来。（`server:` 后面跟一个块是协调器，照常读取——只有旧的单行写法会被拒绝。）
- **一次性命令**在自建设备上不再读 `CALABI_SERVER`、`CALABI_TOKEN`、`CALABI_EDGE_PIN`、`CALABI_EDGE_TRUST`。
- **自建的中继一律核对凭证。** 给它协调器的公钥。
- **协调器提供 TLS。** 没有证书文件时，以前提供明文，现在生成自签证书。在设备上钉住它的指纹，或设 `CALABI_COORD_TLS=off`。
- **`calabi mesh down` 在重启后依然有效**（自建设备上）；不带参数的 `calabi mesh up` 把组网打开。

---

## 常见问题

### 凭证是什么？

凭证是设备向边缘节点出示、用来进门的东西。协调器给每台设备签一份：设备的公钥、所属组网、一小时后到期。
边缘节点接受出示了有效凭证、并能证明自己持有凭证上那把私钥的设备，隧道和中继都是这样。

- 设备每次连边缘节点前向协调器要一份新凭证，剩三分之一有效期时续期。
- 边缘节点自己核对凭证，不问协调器。所以停用或删除一台设备后，它续不了凭证，边缘节点在它手里那份凭证到期时断开它的隧道——
  最多一小时。

### 设备怎么信任边缘节点的证书？

设备从协调器拿到边缘节点的地址和指纹，并钉住这个指纹。

没设 `CALABI_COORD_EDGE_PIN` 时，协调器自己去边缘节点读指纹：读到之前每几秒一次，读到之后每分钟一次。
所以边缘节点换了证书，每台设备都会跟上，不需要谁确认，协调器会记一条日志。读到之前，它不告诉设备任何边缘节点。

这样读只在协调器和边缘节点之间的路径无法被篡改时才安全——同一台机器，或同一个 compose 网络。隔着公网时，请设 `CALABI_COORD_EDGE_PIN`。

### 为什么先核对协调器的证书？

邀请里的密钥是个秘密，设备入网时要把它发给协调器。App 先确定信任哪张证书，确保密钥只发给你的协调器，密钥也最后才用掉。

客户端里还内置了一张 CA，那是 calabi.net 的，连你的协调器时从来不用它。要用你自己的 CA，设 `ca_file:`。

### 为什么吊销密钥不会移除它放进来的设备？

密钥只用于入网。入网之后，设备靠证明自己持有设备私钥来重连，不再需要放它进来的那把密钥。要移除设备，就停用或删除它。

### 为什么 `calabi join` 到不了已安装的服务？

服务是另一个客户端，有自己的数据目录，不是你这个用户的。`calabi join` 把入网信息存给你运行它的那个客户端。
要让服务入网，在它自己的控制台里连接（桌面 App 的窗口，或 `http://127.0.0.1:7400`）；或者运行 `calabi daemon`，在终端里用这次入网。

### 协调器或中继能看到我的流量吗？

不能。每台设备自己生成 WireGuard 私钥，协调器拿不到任何私钥。组网流量在设备之间直连，或经中继转发；中继按设备公钥转发
加密后的包，没有任何能解密的代码：`pkg/relay` 不含边缘节点或控制面代码，由依赖测试保证。

### 设备会往外连什么？

你的协调器，以及协调器告诉它的边缘节点。没有任何统计上报。客户端只有一个写死的外部地址：`download.calabi.net` 上
签名的更新清单，只有登录 calabi.net 的守护进程会去检查，自建的守护进程不会。

### 流量怎么计算？

- 隧道流量：守护进程按隧道上报。
- 经中继的组网流量：只在发送方计一次。
- 设备之间的直连不经过你的服务器，不计。

设备在组网上、或者持续在上报时，算作它的隧道在线。

### 自建的组网和 calabi.net 的一样吗？

一样，是同一份代码：你的协调器有自己的密钥、ACL、中继和设备。calabi.net 在它外面加了账号、组织和计量。

### 一台设备能同时在我的服务器和 calabi.net 上吗？

同一时间只能在一个上面。已登录 calabi.net 时，客户端会先请你退出，再加入你的服务器。`calabi join --replace`
把设备从一台服务器换到另一台。

### 为什么边缘节点那条告警不统计所有失败的请求？

因为大多数失败的请求并不是你的服务器出了问题。

边缘节点给每个访客请求记一个 `outcome`，它们分三类，只有第一类是故障：

- **你的服务器**——`internal_error`、`replay_head_failed`，以及 `global_*` 那一对，后者意味着边缘节点
  已经饱和、在丢流量。
- **你的上游**——`open_upstream_failed`：隧道指向的那个服务拒绝了连接。如果那个服务是你自己跑的，
  它就该由你处理，所以 README 里写了怎么把它加进告警。
- **你的规则**——`rate_limited`、`ip_denied`、`conn_capped`、`daily_capped`、`auth_required`、
  `oauth_redirect`。都是你配的访问控制在正常工作。

`no_tunnel` 和 `sniff_failed` 同样排除在外：一个公网地址会被陌生人持续扫描，在流量小的服务器上，
这类请求很容易比真实请求还多。把它们算进去的告警会天天响，而且什么也说明不了。

想一次看全：

```promql
sum by (proxy_type, outcome) (rate(calabi_edge_visitor_requests_total[5m]))
```

---

## 许可证与贡献

按 [LICENSE](../LICENSE) 中的条款开源（另见 `NOTICE`）。欢迎对边缘节点、客户端、协调器和本地控制台提 issue 和补丁。

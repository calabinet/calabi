<p align="center">
  <img src="docs/images/logo.svg" width="120" height="120" alt="Calabi">
</p>

<h1 align="center">Calabi</h1>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="WireGuard" src="https://img.shields.io/badge/WireGuard-mesh-88171A?style=flat-square&logo=wireguard&logoColor=white">
  <img alt="Platforms" src="https://img.shields.io/badge/Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-amd64%20%C2%B7%20arm64%20%C2%B7%20armv7-4c8bf5?style=flat-square">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-Apache%202.0-3da639?style=flat-square"></a>
  <a href="https://github.com/calabinet/calabi/releases"><img alt="Release" src="https://img.shields.io/github/v/release/calabinet/calabi?style=flat-square&color=22d3ee&label=release"></a>
</p>

<p align="center">
  <a href="#发布产物以及怎么自己验证它"><img alt="可复现构建"
     src="https://img.shields.io/badge/%E5%8F%AF%E5%A4%8D%E7%8E%B0%E6%9E%84%E5%BB%BA-%E6%AF%8F%E4%B8%AA%E7%89%88%E6%9C%AC%E9%83%BD%E8%83%BD%E8%87%AA%E5%B7%B1%E9%87%8D%E7%BC%96%E4%B8%80%E9%81%8D-22d3ee?style=for-the-badge&labelColor=0e1630"></a>
</p>

<p align="center"><b>自托管的内网穿透与私有 WireGuard 组网</b></p>

<p align="center">
  <a href="README.md">English</a> | 中文
</p>

---

同一套代码里的两条路，都用来访问一台没有公网地址的机器；全部跑在你自己的机器
上——不需要账号，不回连，不上报任何数据。

- **隧道（内网穿透）**——把 `calabi-edge` 放在有公网 IP 的主机上。`calabi`
  客户端向它发起**一条**出站 TLS + yamux 连接，边缘节点把公网来的
  HTTP/HTTPS/TCP/UDP 流量顺着这条连接转回你笔记本或局域网里的服务。
  **互联网上的任何人都能访问。**
- **组网（Mesh）**——把你自己的机器连成一张私有 WireGuard 网络，每台拿一个稳定的
  `100.64.0.0/10` 地址。NAT 允许时节点之间直连打洞，打不通时退回你自己跑的中继。
  **只有你的机器能访问。**

```
  TUNNELS — 把公网流量引进来          MESH — 机器之间私下互访

  visitors                                     laptop ─────────────┐
     │                                            │  direct (UDP)  │
     ▼                                            │  hole-punched  │
 ┌──────────────┐                                 ▼                │
 │  calabi-edge │  public IP / DNS             ┌────────┐          │
 └──────┬───────┘                              │ NAT :( │          │
        │ TLS + yamux                          └────────┘          ▼
        │ (client dialed OUT)                      │            server
        ▼                                          ▼           (no public IP)
 ┌──────────────┐                          ┌───────────────┐
 │    calabi    │ ──► 127.0.0.1:8080       │  calabi-edge  │  relay: ciphertext
 └──────────────┘                          │  role: relay  │  only, never decrypts
   your laptop                             └───────────────┘

              calabi-coord — 组网的协调器
```

- 左边：`calabi-edge` 在公网 IP 上收访问者的流量，`calabi` 从内网拨出一条
  TLS + yamux 连接，流量顺着它回到 `127.0.0.1:8080`。
- 右边：两个节点能打洞就直连（UDP）；打不通就走 `role: relay` 的
  `calabi-edge` 中继——它只转密文，永远不解密。
- `calabi-coord` 是组网的协调器：谁在网里、每个节点分到什么地址、谁可以访问谁。

两种模式都不需要在你的机器上开任何入站端口：连接都是客户端拨出去的。

---

## 三个二进制

| 程序 | 是什么 | 跑在哪 |
|---|---|---|
| `calabi` | 客户端——开隧道、加入组网、提供本地 Web 控制台 | 你的笔记本、服务器、树莓派 |
| `calabi-edge` | 数据面。`role: edge` 接公网流量做隧道；`role: relay` 是组网中继 + STUN 探测；`role: both` 两者都做 | 有公网 IP 的主机 |
| `calabi-coord` | 组网协调器——节点注册、地址分配、ACL、MagicDNS、中继目录 | 一台你的节点能连到的主机 |

纯 Go、`CGO_ENABLED=0`、无运行时依赖。只想要隧道的话，用其中两个就够，
完全不用管 `calabi-coord`。

---

## 隧道

- **HTTP / HTTPS / TCP / UDP**——Web 应用、SSH、数据库、游戏服，任何跑在
  TCP/UDP 上的东西。
- **单条多路复用连接**——每个客户端只保持一条出站 TLS + yamux 会话，你这边
  不需要开端口、不需要做端口映射。
- **自定义域名 + HTTPS**——把 DNS 指到你的边缘节点，就能把隧道绑到
  `app.example.com`；HTTPS 也可以由边缘终止。
- **按隧道的访问控制**——任意隧道都能配 IP 黑白名单；Web 隧道还支持 HTTP Basic
  认证、OAuth（Google / GitHub）、请求头注入与删除、限速。Basic 认证的密码在
  本地就用 bcrypt 哈希过，明文不会离开你的机器。
- **守护进程（supervisor）**——一个 YAML 文件管所有隧道，单进程运行、断线自动重连，
  还能装成开机自启的系统服务（Windows 服务 / systemd / launchd），崩溃自动拉起。

## 组网

- **就是 WireGuard**——数据面是真的 WireGuard，密钥在每个节点本地生成。
  `calabi-coord` 拿不到私钥，也看不到明文。
- **能直连就直连，不能才走中继**——节点互相发现对方的端点，用 STUN 测到各个
  中继的延迟来选归属区域，然后打洞。走中继是兜底方案，不是常态。
- **中继是你自己的**——`calabi-edge` 配 `role: relay` 就是中继。它按节点公钥
  转发**已经加密好的**报文，**没有能力解密**；这个隔离是结构性的——由依赖关系
  测试钉死，而不是靠一个配置开关。中继可以只跑一台，也可以在多个地区各跑一台。
- **稳定地址 + MagicDNS**——每个节点拿到一个 `100.64.0.0/10` 地址，换网络也不变，
  并带一个名字（把名字接进操作系统解析目前只支持 Linux；地址本身各平台都可用）。
- **ACL**——一个 JSON 策略文件，用分组和规则描述谁能访问谁的哪些端口。改了热加载，
  而且文件写坏时**失败关闭**（全部拒绝），绝不放行。
- **子网路由与出口节点**——让某个节点把它背后的整个局域网通告给全网，或者把某台
  机器的默认路由从另一个节点走出去。通告在所有平台都能用；真正做转发/NAT 的那一半
  目前在 Linux 上是自动配好的。
- **按天区分直连与中继**——本地控制台把组网流量分成「直连」和「中继」两条统计，
  你能直接看到到底有多少流量真的需要中继。

## 本地控制台

守护进程运行时会在 **`http://127.0.0.1:7400`** 提供一个 Web 控制台：隧道列表和
实时流量、请求检查器（可一键重放）、组网对端及其当前传输路径、日志，以及直接在
浏览器里新建 / 编辑 / 删除隧道。它只通过 loopback 和本地守护进程通信。界面支持
10 种语言。

---

## 编译

需要 Go 1.25+。

```bash
make build          # → bin/calabi, bin/calabi-edge, bin/calabi-coord
```

或者直接编（Windows 上把输出名写成 `*.exe`）：

```bash
( cd apps/client       && go build -o calabi       ./cmd/calabi )
( cd apps/calabi-edge  && go build -o calabi-edge  ./cmd/calabi-edge )
( cd apps/calabi-coord && go build -o calabi-coord ./cmd/calabi-coord )
```

`make build` 在 Windows 上会自动加 `.exe`。交叉编译：
`GOOS=windows GOARCH=amd64 go build -o calabi-edge.exe ./cmd/calabi-edge`。

---

## 五分钟上手 —— 一条隧道

```bash
# 1. 边缘节点，放在有公网 IP 的主机上（想先试的话本地跑也行）
./calabi-edge                                 # :7443 控制, :8080 http

# 2. 一个要暴露出去的本地服务
python3 -m http.server 9000

# 3. 客户端，指向你的边缘节点
export CALABI_SERVER=127.0.0.1:7443
export CALABI_TOKEN=dev-token-please-change
export CALABI_INSECURE=1                       # 开发用：边缘是自签证书
./calabi http 9000 --domain app.localtest.me

# 4. 通过边缘访问
curl http://127.0.0.1:8080/ -H 'Host: app.localtest.me'
```

多条隧道 + 自动重连 + 控制台：

```bash
./calabi daemon --config tunnels.yaml   # 然后打开 http://127.0.0.1:7400
```

## 五分钟上手 —— 一张组网

一个协调器、一台中继，节点想加多少加多少。

```bash
# 1. 中继 —— calabi-edge 跑 relay 角色，放在有公网 IP 的主机上。
#    中继不需要任何配置文件：没有域名，也不需要证书。
CALABI_EDGE_ROLE=relay CALABI_EDGE_RELAY_LABEL=home \
  ./calabi-edge                               # :3340 中继(TCP), :3478 STUN(UDP)

# 2. 协调器。authkeys.json 把认证密钥映射到某张网（可带 ACL 标签）：
#      { "my-secret-key": { "meshnet": 1, "tags": ["tag:laptop"] } }
CALABI_COORD_AUTHKEYS_FILE=./authkeys.json \
CALABI_COORD_DERP_ADDR=relay.example.com:3340 \
CALABI_COORD_DERP_STUN_PORT=3478 \
CALABI_COORD_GRPC_ADDR=:7012 \
./calabi-coord

# 3. 每个节点加入（需要 tun 设备和管理员权限；
#    Windows 的 wintun.dll 已经内嵌在二进制里，开箱即用）
sudo ./calabi mesh up \
  --coord coord.example.com:7012 \
  --relay relay.example.com:3340 \
  --auth-key my-secret-key --name laptop

./calabi mesh status
```

然后在节点之间 `ping 100.64.0.x` —— 任何一端都不用做端口映射。

> **节点到协调器这段的 TLS。** 客户端默认用 TLS 连协调器，并用编译进二进制的 CA
> 校验它。自己部署时有两条路：给 `calabi-coord` 签一张你自己 CA 的证书，节点侧用
> `CALABI_EDGE_CA_FILE=/path/to/your-ca.pem` 指过去；或者——**仅限可信网络**——用
> `CALABI_INSECURE=1` 走明文。**认证密钥是从这条连接上发过去的**，所以不要在公网
> 上跑明文。

想让组网以后台服务方式跑（而不是前台占着终端），在守护进程配置里加一段 `mesh:`，
然后 `calabi daemon install`。

**完整文档**——边缘节点配置、按隧道的安全策略、守护进程、装成系统服务、可写的
`:7400` 控制台、HTTPS，以及组网的细节：见
**[docs/self-hosting.zh-CN.md](docs/self-hosting.zh-CN.md)**（英文版：[self-hosting.md](docs/self-hosting.md)）。

---

## 发布产物，以及怎么自己验证它

每个版本都发到两个地方，**文件完全一样**：本仓库的
[GitHub Releases](https://github.com/calabinet/calabi/releases)，以及
`download.calabi.net`。版本号一致、字节一致——GitHub Release 不是另跑一次 CI 编出来的，
就是同一批产物上传上去的。

把源码公开的意义在于：你不必相信我们对二进制里有什么的说法。**官方产物就是从本仓库
编出来的**，不是从内部代码树，而且每个版本都附一份 `build-manifest.json`，写明具体
commit、Go 版本、编译参数，以及唯一一个不在本仓库里的输入（平台的 edge-CA 根证书
——一张公开证书，原文抄在 manifest 里）。你可以自己重编一遍：

```bash
curl -fsSLO https://download.calabi.net/latest/build-manifest.json
bash scripts/verify-reproducible-build.sh build-manifest.json
```

它会按 manifest 指名的 commit 克隆本仓库，重新编译每一个发布的二进制，然后比对哈希。
需要和 manifest 里同一个 Go 版本——版本不同是校验失败最常见的原因，脚本会在最开头
就把这一点说清楚。

它比对的是**二进制**，不是你下载的 `.zip` / `.tar.gz`，因为压缩包本身不可复现：
tar+gzip 和 zip 都会记录修改时间，同样的字节隔一秒再打包，哈希就变了。压缩包用
`SHA256SUMS` 校验——那回答的是「我下载的文件完整吗」，和「它是不是从这份源码编出来的」
是两个问题。

**目前还没覆盖到的部分**（manifest 里自己列着，免得这个说法变成半真半假）：Windows
桌面安装器和 macOS `.pkg`（各自是独立的 Rust/Tauri 工具链）、docker 镜像，以及两个
以二进制形式提交进仓库、而不是在这里编出来的输入——本地控制台编译好的前端包，和
第三方的 `wintun.dll`。对同一个 commit 来说它们的字节是确定的，但本仓库没有从它们
各自的源码推导出来。

---

## 常见用法

- 让 webhook、OAuth 回调打到你笔记本上的服务做联调。
- 把还在改的开发服务临时分享给同事或客户看。
- 访问 NAT / CGNAT 后面的家庭实验室、NAS、树莓派——想让公网看到就开隧道，
  只想自己看就走组网。
- 通过 TCP 隧道或组网访问远端机器的 SSH、数据库端口。
- 把分散在几个云上的机器连成一张扁平的私有网络，不用去打通 VPC 对等连接。
- 用出口节点把笔记本的流量从家里那台机器走出去。

## 参与贡献

欢迎给边缘节点、客户端、协调器和本地控制台提 issue 和补丁。我们用 **DCO**
（开发者原创声明）而不是 CLA——每个 commit 加一行签名即可：

```bash
git commit -s -m "your message"
```

细节见 [CONTRIBUTING.md](CONTRIBUTING.md) 和 [DCO](DCO)。PR 上有 CI 检查这个签名。

## 许可证

按 [LICENSE](LICENSE)（Apache-2.0）开源。

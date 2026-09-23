<p align="center">
  <img src="docs/images/logo.svg" width="120" height="120" alt="Calabi">
</p>

<h1 align="center">Calabi</h1>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="WireGuard" src="https://img.shields.io/badge/WireGuard-mesh-88171A?style=flat-square&logo=wireguard&logoColor=white">
  <img alt="Platforms" src="https://img.shields.io/badge/Linux%20%C2%B7%20macOS%20%C2%B7%20Windows%20%C2%B7%20Android-amd64%20%C2%B7%20arm64%20%C2%B7%20armv7-4c8bf5?style=flat-square">
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

## Calabi 是什么？

Calabi 让一台没有公网地址的机器变得可以访问——NAT 后面的笔记本、CGNAT 后面的
服务器、公司内网里的机器。两条路：

- **隧道（内网穿透）**——把 `calabi-edge` 放在有公网 IP 的主机上。`calabi`
  客户端向它发起**一条**出站 TLS + yamux 连接，边缘节点把公网来的
  HTTP/HTTPS/TCP/UDP 流量顺着这条连接转回你笔记本或局域网里的服务。
  **互联网上的任何人都能访问。**
- **组网（Mesh）**——把你自己的机器连成一张私有 WireGuard 网络，每台拿一个稳定的
  `100.64.0.0/10` 地址。NAT 允许时设备之间直连打洞，打不通时退回你自己跑的中继。
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
 └──────────────┘                          │  role: mesh   │  only, never decrypts
   your laptop                             └───────────────┘

              calabi-coord — 每台设备的身份
```

- 左边：`calabi-edge` 在公网 IP 上收访问者的流量，`calabi` 从内网拨出一条
  TLS + yamux 连接，流量顺着它回到 `127.0.0.1:8080`。
- 右边：两台设备能打洞就直连（UDP）；打不通就走 `role: mesh` 的
  `calabi-edge` 中继——它只转密文，永远不解密。
- `calabi-coord` 是每台设备的身份：谁入了网、边缘节点在哪、每台设备的组网地址、谁可以访问谁。

两种模式都不需要在你的机器上开任何入站端口：连接都是客户端拨出去的。

`calabi-coord` 和 `calabi-edge` 合起来就是你的服务器。设备用邀请入网一次，从此隧道和组网都能用；
组网可以在某台设备上关掉，它的隧道照常运行。

### 这个仓库里有什么

数据面：`calabi` 客户端、`calabi-edge` 数据节点、`calabi-coord` 协调器。
在自己的机器上跑隧道和组网所需要的东西，这里都有。自建时不需要账号，也不连我们的任何服务。

仓库里还有 Android App：用邀请加入你自己的服务器，或者登录 calabi.net、加入那个
组织的组网。

托管平台 [calabi.net](https://calabi.net) 跑的是同一份数据面，在它外面加上控制面：
账号与组织、托管在多个地域的边缘节点、团队权限、用量与计费，以及网页控制台。
那部分是另一个产品，不在这个仓库里。

---

## 三个程序和一个 Android App

| 组件 | 是什么 | 跑在哪 |
|---|---|---|
| `calabi` | 客户端——开隧道、加入组网、提供本地 Web 控制台 | 你的笔记本、服务器、树莓派 |
| `calabi-edge` | 数据面。`role: tunnel` 接公网流量做隧道；`role: mesh` 是组网中继 + STUN 探测；`role: both` 两者都做 | 有公网 IP 的主机 |
| `calabi-coord` | 协调器——每台设备的身份：邀请、设备登记、地址分配、ACL；告诉设备边缘节点在哪、签发边缘节点认的凭证 | 一台你的设备能连到的主机 |
| Android App | 把手机作为一台设备加入组网（你自己服务器的，或你在 calabi.net 上的组织的），支持出口设备和快捷设置磁贴；隧道和用量只读 | Android 8.0 及以上的手机（arm64、armv7） |

三个程序都是纯 Go、`CGO_ENABLED=0`、无运行时依赖。`calabi-coord` 和 `calabi-edge` 合起来是你的
服务器，客户端跑在每台设备上。

Android App（`apps/client-android`）是 Kotlin 写的界面，里面是同一份 Go 客户端代码，
用 gomobile 绑定进来（`apps/client/mobile`）。

---

## 你的服务器

- **邀请**——`calabi-coord invite` 打印一条 `calabi://join` 链接、一个二维码，以及等价的
  `calabi join` 命令行。默认一份邀请放进一台设备，24 小时内有效。
- **入网就是登录**——协调器告诉设备边缘节点在哪，并签发边缘节点放它进来所认的凭证。
  凭证有效期一小时，设备自己续。
- **设备**——`calabi-coord device list | approve | disable | enable | delete`。
  停用或删除的设备，协调器立刻拒绝；边缘节点在它的凭证到期时拒绝，最长一小时。
- **隧道和流量集中在一处**——每个入网的守护进程把自己的隧道报给协调器；协调器有数据库时
  按小时记下它们的流量，保留 92 天。手机和控制台都能看。

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
- **一个守护进程**——一台设备的所有隧道在一个进程里、断线自动重连，可以在控制台里建，
  也可以从 YAML 文件读，还能装成开机自启的系统服务（Windows 服务 / systemd / launchd）。

## 组网

- **WireGuard**——每台设备自己生成密钥。`calabi-coord` 拿不到私钥，也看不到你的流量。
- **能直连就直连**——设备找到彼此的地址，穿过 NAT 直接连接；连不上时，流量走中继。
- **中继是你自己的**——`calabi-edge` 配 `role: mesh`（或 `both`，`deploy/server` 就是这么跑的）。
  它在设备之间转发加密后的包，没有任何能解密的代码。中继可以只跑一台，也可以在多个地区各跑一台。
- **稳定地址**——每台设备拿到一个 `100.64.0.0/10` 地址，换网络也不变，
  各平台都可用。
- **每台设备一个开关**——`calabi mesh down`（或在控制台里）让设备退出组网，隧道照常运行；
  `calabi mesh up` 再加回来。
- **ACL**——一个 JSON 策略文件，用分组和规则描述谁能访问谁的哪些端口。改了会重新加载；文件写坏时拒绝所有流量。
- **子网路由与出口设备**——把某台设备背后的局域网共享给整个组网，或者让一台设备的上网流量从另一台出去。
  Linux 设备可以共享子网、当出口设备，转发和 NAT 自动配好；各平台的设备都能使用它们。
- **按天区分直连与中继**——本地控制台把组网流量分成「直连」和「中继」两条统计，
  你能直接看到到底有多少流量真的需要中继。

## 本地控制台

守护进程运行时会在 **`http://127.0.0.1:7400`** 提供一个 Web 控制台：隧道列表和
实时流量、请求检查器（可一键重放）、组网对端及其当前传输路径、日志，以及直接在
浏览器里新建 / 编辑 / 删除隧道。它只通过 loopback 和本地守护进程通信。机器连你自己的
服务器也在这里：粘贴邀请即可，不用手写配置文件。入网后，它还显示你服务器上的所有隧道和本月流量。
界面支持 10 种语言。

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

每个版本也提供这三个程序的现成二进制，各 7 个平台（`calabi-coord` 从 1.13 起），三个程序也各有
Docker 镜像：`calabinet/calabi`、`calabinet/calabi-edge`、`calabinet/calabi-coord`。它们都从这个仓库
编译，见[下文](#发布产物以及怎么自己验证它)。

### Android App

需要 JDK 17、Android SDK（platform 35）和 NDK r27，以及 gomobile。先用
`scripts/mobile/build-core-android.ps1`（PowerShell 脚本，按 Windows 写的）把 Go 核心编成
`.aar`，再用 Gradle 编 App。步骤见
[apps/client-android/README.md](apps/client-android/README.md)。

---

## 五分钟上手 —— 你自己的服务器

`calabi-coord` 和 `calabi-edge` 合起来就是你的服务器。在一台有公网地址、装了 Docker Compose（或 `podman compose`）的 Linux 机器上，
[`deploy/server`](deploy/server) 用一份 `.env` 把两者一起跑起来：

```bash
cd deploy/server
cp .env.example .env     # 填 CALABI_PUBLIC_HOST、CALABI_ADMIN_TOKEN；要 HTTP 隧道再填 CALABI_TUNNEL_DOMAIN
docker compose up -d

# 给每台设备一份邀请：一条 calabi://join 链接和一个二维码
docker compose exec coord calabi-coord invite --note laptop
```

开放 7012 和 7443（设备）、80 和 443（HTTP 隧道）、20000–20999 tcp/udp（TCP、UDP 隧道）、3340 和 3478/udp（组网中继）。

然后在每台设备上——Android App 则扫二维码：

```bash
calabi join "calabi://join?…"    # 入网就是登录：隧道和组网现在都能用了
calabi http 8080                 # → https://u000001.<你的隧道域名>
ping 100.64.0.2                  # 另一台设备，走 WireGuard
```

入网后，客户端的守护进程就在运行。在它的控制台 `http://127.0.0.1:7400` 里可以新建隧道、开关组网；组网关着时隧道照常。
不用抄 token，也不用确认边缘节点的证书：两者都由协调器提供。

**完整文档**——不用 Docker 直接跑程序、协调器和边缘节点的每一项设置、按隧道的安全策略、用配置文件自动入网的
服务器和批量设备、`:7400` 控制台、ACL、子网路由和出口设备：见
**[docs/self-hosting.zh-CN.md](docs/self-hosting.zh-CN.md)**（英文版：[self-hosting.md](docs/self-hosting.md)）。

---

## 发布产物，以及怎么自己验证它

每个版本都发布在本仓库的 [GitHub Releases](https://github.com/calabinet/calabi/releases)
和 `download.calabi.net`，两边的文件完全一样。

**官方二进制就是从本仓库编出来的。** 每个版本都附一份 `build-manifest.json`，写明 commit、Go 版本、编译参数，
以及唯一一个来自本仓库之外的输入：平台的 edge-CA 根证书，一张公开证书，原文附在 manifest 里。
重编所有发布的二进制并比对：

```bash
curl -fsSLO https://download.calabi.net/latest/build-manifest.json
bash scripts/verify-reproducible-build.sh build-manifest.json
```

脚本按 manifest 里的 commit 克隆本仓库，重编每个二进制并比对哈希。它需要 manifest 里写的 Go 版本，会先检查这一点。

它比对的是二进制，不是压缩包（[为什么](#为什么比对二进制而不是压缩包)）。下载的压缩包用 `SHA256SUMS` 校验。

**manifest 没覆盖的**（manifest 里也列着）：

- Windows 安装包和 macOS `.pkg`（用 Rust 和 Tauri 构建）；
- Docker 镜像；
- 两个直接提交进仓库、不在这里编译的文件：本地控制台编译好的前端包，和 `wintun.dll`；
- Android APK（[为什么](#为什么-android-apk-不可复现)）。每个版本的发布说明里都印着它的签名证书，安装前可以核对：

```bash
apksigner verify --print-certs calabi-android.apk
```

---

## 常见用法

- 让 webhook、OAuth 回调打到你笔记本上的服务做联调。
- 把还在改的开发服务临时分享给同事或客户看。
- 访问 NAT / CGNAT 后面的家庭实验室、NAS、树莓派——想让公网看到就开隧道，
  只想自己看就走组网。
- 通过 TCP 隧道或组网访问远端机器的 SSH、数据库端口。
- 把分散在几个云上的机器连成一张扁平的私有网络，不用去打通 VPC 对等连接。
- 用出口设备把笔记本的流量从家里那台机器走出去。
- 用 Android 手机通过你自己的组网、或 calabi.net 的组网访问自己的机器。

## 常见问题

### 为什么比对二进制而不是压缩包？

压缩包不可复现：tar、gzip 和 zip 都会记录文件时间，同一个二进制打两次包，压缩包的哈希就不同。
`SHA256SUMS` 回答「下载的文件完整吗」，manifest 回答「里面的二进制是不是从这份源码编出来的」。

### 为什么 Android APK 不可复现？

它的 Go 核心里记着编译时所在的目录，同一个 commit 换个目录编，得到的库就不一样。

## 参与贡献

欢迎给边缘节点、客户端、协调器、本地控制台和 Android App 提 issue 和补丁。每个 commit 都要带
**DCO** 签名（开发者原创声明），不需要签 CLA：

```bash
git commit -s -m "your message"
```

- **[CONTRIBUTING.md](CONTRIBUTING.md)**——这里收什么改动，以及一个 PR 怎么进到发布的二进制里。
- **[DEVELOPMENT.md](DEVELOPMENT.md)**——在一台机器上把三个程序编出来跑通，不需要账号，也不需要公网地址。
- **[SECURITY.md](SECURITY.md)**——怎么报告安全漏洞。走私下渠道，别开 issue。

每个 PR 上，CI 都会在 Linux、macOS 和 Windows 上构建、检查并跑测试，也会检查签名。

## 许可证

按 [LICENSE](LICENSE)（Apache-2.0）开源。

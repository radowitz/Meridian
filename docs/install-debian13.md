# 在 Debian 13 上安装

目标机器是一台新的 Debian 13，和 ROS `192.168.100.1` 在同一个二层，地址 `192.168.100.88/24`。不要改 ROS，不要停旧的 mihomo，也不要把这台机器的上游接到旧网关后面。

## 1. 地址和转发

局域网口静态地址示例（接口名按实际修改，下面用 `eth0`；Debian 13 常见的是 `ens192` 之类）：

```text
address 192.168.100.88/24
gateway 192.168.100.1
```

默认路由经 ROS，这样机器自己的更新和 WireGuard 外层握手走国内出口。策略路由只处理从测试设备转发进来的流量。

确认没有在这台机器上启用 radvd 或 DHCP。地址 `192.168.100.1` 必须仍然是 ROS。

面板拓扑里网关局域网口只认 `settings.lan_interface`（nft 兜底表、路由、sysctl、开机等待、`meridian-verify.sh` 都用它）。网关节点自己的 `lan_interface` 要么留空，要么和它相同，不同会被校验拒绝；面板里选中网关节点时编辑的就是这一项。

地址若由 DHCP 下发（ifupdown 的 `allow-hotplug`），`network-online.target` 往往在拿到租约之前就到了。`meridian-up.sh` 因此在加载防火墙和兜底表之后、打开转发和装路由之前，最多等 60 秒：局域网口存在且已 up、带着配置的网关地址、ROS 的 IPv4 下一跳在本链路上。等不到就以 `meridian-lan-not-ready` 和退出码 75 失败（此时没有打开转发、没有装路由，兜底表照常 fail-closed），`meridian.service` 只对这个退出码每 15 秒自动重试（30 分钟内最多 20 次），租约来了就自己恢复。其他失败（nft 批次、兜底表、WireGuard）不自动重试，要人看。IPv6 不等：路由只用 ROS 的链路本地下一跳加显式网卡，接口在就能装；网关自己的 RA 默认路由晚到不影响 IPv4 数据面。查看：`journalctl -b -u meridian.service`。

## 2. 主机准备

```bash
sudo bash deploy/debian/install.sh
```

脚本按本机状态自己判断两种模式（不是参数）：

- **首次准备**：`/usr/local/sbin/meridian-up.sh` 还不是可执行文件，或 `/etc/systemd/system/meridian.service` 不存在（面板还没在这台机器上「安装到本机」过）。
- **升级已有安装**：两者都在。见下面「升级」。

首次准备时脚本会：

- 写入并应用 `/etc/sysctl.d/99-meridian.conf`（开机时转发保持关闭、`rp_filter=2`、关闭发送重定向、局域网口 `accept_ra=2`）；转发由 `meridian-up.sh` 在防火墙和兜底表加载之后打开，脚本结束时 IPv4 / IPv6 转发都是关的
- 若存在 systemd-resolved，关掉它的 53 端口占用，把 53 留给 SmartDNS
- **先**写 `/etc/docker/daemon.json`（`iptables` / `ip6tables` / `ip-forward` 都为 false，仅当还没有这个文件），**再**用发行版软件包安装 `docker.io`、`docker-compose-v2`（没有这个包时才用 `docker-compose`）、`wireguard-tools`、`nftables`、`openssl`。apt 装完会立刻启动 dockerd；如果它先用默认设置启动，会打开 IPv4 转发并把 iptables 的 FORWARD 策略改成 DROP，网关在下次重启前不转发任何 IPv4 流量
- Docker 启动后再把转发关掉（这台机器上还没有数据面）；如果 `iptables -S FORWARD` / `ip6tables -S FORWARD` 仍显示 `-P FORWARD DROP`（以前装过 Docker 的机器），脚本用 `!!!` 醒目提示并在最后再提醒一次：**重启本机即可清除**（Docker 不会再建它）；确认没有别的程序依赖时也可手动 `iptables -P FORWARD ACCEPT`。提示出现时先重启，再去面板安装
- 把 `/etc/wireguard` 设成 0700（已存在也收紧）
- 启用 `meridian.service`，开机时若 `/usr/local/sbin/meridian-up.sh` 已存在就只恢复 Meridian 自己的表和路由；启用 `meridian-guard.service`，开机时先于 systemd-sysctl 和 Docker 加载局域网兜底表
- 构建面板镜像，把同一个 `meridian` 二进制复制到 `/usr/local/bin`，生成 `/etc/meridian-host/agent.token`（0600），启动 `meridian-host.service`。面板容器只能通过它的 root-only socket 请求固定动作（激活、健康检查、回滚），没有 `NET_ADMIN`、`/dev/net/tun` 或 systemd。`meridian-host` 没运行时，面板的「安装到本机」会直接报错，不会假装成功
- 不停止、不修改任何名字里带 mihomo 的服务

脚本不会自动改网卡地址。如果当前没有 `192.168.100.88`，它只打印警告。

网关走国内线路时，`deb.debian.org` 可能非常慢（实测约 30 KiB/s），`apt-get` 一步就要很久。可以先把 `/etc/apt/sources.list.d/` 换成更近的 Debian 镜像，或事先在别处下载好这些 `.deb` 再装；脚本本身不改 apt 源。

### 升级

升级就是在网关上用新代码再跑一次同一个脚本（离线镜像的话带上 `MERIDIAN_IMAGE_TAR`，见下节）。检测到已有安装时，脚本：

- **不**向内核写任何转发 sysctl，**不**执行 `sysctl --system`，不重写面板管理的 `99-meridian.conf`（只把旧版本留下的「开机即打开转发」行在文件里改成 0，运行中的值不变）；Docker 只在刚写了 `daemon.json` 或它本来没运行时才重启
- 先把当前的 `/usr/local/bin/meridian` 和三个 unit 文件备份到 `/var/lib/meridian-host/upgrade-backup`，再换成新版本、`daemon-reload`、重启 `meridian-host`（正在运行的 `meridian.service` 不会因 `daemon-reload` 重启）
- 升级前数据面在运行且双栈转发都开着：运行 `meridian host-restore`，经 `meridian-host` 检查 `meridian.service` 处于 active、`inet meridian` 和 `inet meridian_guard` 都在（两次采样），并确认转发仍开着；不满足时经同一个 agent 动作重新激活（重启 `meridian.service`，即开机时同样的 `meridian-up.sh`），再查一遍
- 升级前数据面在运行但转发不是双栈全开：只做健康检查（`host-restore --health-only`），什么都不重启
- 升级前数据面没有运行：保持原样，不打开转发，最后提示去面板安装或修好原因后 `systemctl restart meridian.service`
- 以上任何一步失败（含新版 `meridian-host` 起不来）：把备份的二进制和 unit 放回去、重启旧版 `meridian-host`；数据面升级前在运行而现在没有就再启动一次 `meridian.service`；升级前是关的转发再关上；打印当前数据面和转发状态，退出码 1

无论哪种模式，脚本开始时为 0 的转发项在结束时仍是 0。之后用新镜像重建面板容器（不影响数据面）：

```bash
sudo docker compose -f deploy/docker-compose.yml up -d            # 或离线镜像：up -d --no-build
```

升级后建议核对：`systemctl is-active meridian.service`、`sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding`（升级前是 1 的仍是 1），并跑一次 `sudo /usr/local/sbin/meridian-verify.sh`。

### 网关访问不了 Docker Hub 时

网关自己的流量按设计走 ROS 的国内出口，Docker Hub 和 `proxy.golang.org` 通常连不上，脚本里的镜像构建会超时。这时在一台能访问它们的机器上构建并导出，再让脚本加载，网关上不拉取任何镜像：

```bash
# 在开发机上（仓库根目录）。平台按网关的架构写，x86_64 是 linux/amd64。
docker buildx build --platform linux/amd64 -f deploy/Dockerfile -t meridian:local --load .
docker pull --platform linux/amd64 pymumu/smartdns:latest
docker save meridian:local pymumu/smartdns:latest | gzip > meridian-images.tar.gz
scp meridian-images.tar.gz root@192.168.100.88:/root/

# 在网关上
sudo MERIDIAN_IMAGE_TAR=/root/meridian-images.tar.gz bash deploy/debian/install.sh
```

脚本会检查镜像包里有 `meridian:local`，并且架构和本机一致。之后启动面板和 SmartDNS 时加 `--no-build`，Compose 就直接用已加载的镜像：

```bash
sudo docker compose -f deploy/docker-compose.yml up -d --no-build
sudo docker compose -f deploy/docker-compose.yml --profile dns up -d --no-build
```

升级时重复同样的步骤：重新构建、导出、带 `MERIDIAN_IMAGE_TAR` 再跑一次脚本（按上面「升级」处理：换二进制、重启 `meridian-host`、经它检查并在需要时恢复数据面），然后 `up -d --no-build`。

## 3. 启动面板

```bash
sudo docker compose -f deploy/docker-compose.yml up -d --build
```

容器使用 host 网络，只为绑定局域网地址；它通过挂载写 Meridian 自己的文件，运行态动作都交给宿主上的 `meridian-host`（挂载 `/run/meridian-host` 和只读口令）。面板默认只绑 `192.168.100.88:8787`。不用 Docker、直接在宿主上跑面板时，以 root 运行 `meridian`，并让 `MERIDIAN_HOST_SOCKET` / `MERIDIAN_HOST_TOKEN_FILE` 指向同一个 socket 和口令（默认值就是 `/run/meridian-host/agent.sock` 和 `/etc/meridian-host/agent.token`）。进程拒绝监听 `0.0.0.0`，避免把面板暴露到非局域网地址。

首次启动会在面板的数据目录里写入口令文件 `panel.token`（权限 0600），日志里只有文件路径。用 Compose 运行时，`/var/lib/meridian` 是**面板容器里**的路径，背后是命名卷 `meridian-data`；宿主上的 `/var/lib/meridian` 只有为 SmartDNS 绑定的 `geosite`、`keywords` 两个子目录，所以在宿主上直接 `cat /var/lib/meridian/panel.token` 通常读不到（文件不存在）。从面板容器里读：

```bash
sudo docker compose -f deploy/docker-compose.yml exec meridian cat /var/lib/meridian/panel.token
```

`meridian` 是 Compose 里的服务名。命名卷在宿主上的实际位置由 Docker 管理（一般在 `/var/lib/docker/volumes/` 下，随 Compose 项目名变化），不要依赖它，也不要为了读口令把整个数据卷改成宿主绑定：这个卷里还有存着 WireGuard 私钥的数据库。不用 Docker、直接在宿主上跑面板时，文件就在 `MERIDIAN_DATA`（默认 `/var/lib/meridian`）下，`sudo cat` 即可。

浏览器打开 `http://192.168.100.88:8787`，把这串口令填进面板。也可以事先设置 `MERIDIAN_TOKEN`。

Debian 13 上请用 `docker compose`（来自 `docker-compose-v2`）。只有旧的 `docker-compose` 命令时，用那一个；这份 Compose 文件需要 v2 的 `profiles`。

## 4. 换成真实端点再下发

仓库和面板里的初始拓扑是文档地址：

- `203.0.113.0/24`、`198.51.100.0/24`：出口和中继的公网 IPv4
- `2001:db8:100::/64`：局域网 IPv6 前缀占位，改成运营商实际委派的 /64
- `fe80::1`：改成 ROS bridge 上的真实链路本地地址
- `example.invalid`、`example-wss-path-prefix`：管理域名和 WSS 路径前缀

在每个 WSS 服务端放上正式证书（Let's Encrypt 或你自己的 CA），路径是 `/etc/meridian/tls/fullchain.pem` 和 `privkey.pem`。wstunnel 自带的证书会被识别，不要用。

私钥由装机时生成，API 返回给浏览器时会打成 `***`。不要把私钥、面板数据目录或 `/var/lib/meridian` 提交进 git。

下发分三步：

1. **校验路径**。缺 IX、Mesh 绕过、NAT 方向错误、Netflix 没走家宽、网关节点的 `lan_interface` 和 `settings.lan_interface` 不一致，都会报错并拒绝保存。
2. **演练**。只产生差分，不写文件。
3. **写入数据目录**，确认后再 **安装到本机**。安装只会覆盖和删除受管清单里属于 Meridian 的 WireGuard、nftables、sysctl、SmartDNS、unit 和脚本，nft 以单个事务替换；随后经 `meridian-host` 启动服务并做健康检查，任一步失败即停止并补偿回安装前。**回滚（含宿主网络）** 把宿主和数据目录一起恢复到上一份，删除新版本引入的文件、接口和服务。实机验收：`sudo bash deploy/verify-host-exec.sh`。

「安装到本机」还要求本机每条 WireGuard 隧道对端节点都有可用的公钥（44 字符 base64）。初始拓扑里对端是占位符：这时安装直接以 422 拒绝并列出缺公钥的节点，不生成网关密钥、不写宿主文件、不动快照；编译、预览、演练和差分照常可用。先给对端生成密钥（「生成脚本」/ provision 的 `generate_keys`）或把公钥填进拓扑。

远程节点用面板里的「生成脚本」演练。确认无误后，用你自己的 SSH 密钥调用 `POST /api/provision`（`dry_run=false`）。演练响应里不会出现新生成的私钥明文。

wstunnel 需要单独安装到 `/usr/local/bin/wstunnel`，版本请钉死你核对过的 [erebe/wstunnel](https://github.com/erebe/wstunnel/releases) release。脚本不会从网络上直接下载二进制。

## 5. 名单

在网关上，配置安装好并且 nftables 表已经存在之后：

```bash
sudo /usr/local/sbin/meridian-update-chnroute.sh
sudo /usr/local/sbin/meridian-update-geosite.sh
sudo docker restart meridian-smartdns        # 宿主上装的 SmartDNS 则是 systemctl restart smartdns
```

默认从 `raw.githubusercontent.com` 下载。网关自己的流量走国内线路，这个地址常常连不上（实测超时）。两个脚本都给每次下载设了连接超时、总超时和少量重试，并且：

- 下载失败、超时、内容为空或不像名单（比如一张 HTML 错误页）时，**不替换**已有的名单文件，chnroute 脚本也**不清空**对应的 nft 集合（清空和写入新元素在同一个 nft 事务里，只在新名单完整且非空时执行）
- 什么都没拿到时退出码 1 并说明原因；只更新了一部分时退出码 2

下载地址和超时用环境变量覆盖，不需要改生成的脚本（脚本不读任何配置文件：`/etc/meridian` 面板容器可写，而这两个脚本以 root 运行）：

| 变量 | 含义 | 默认 |
| --- | --- | --- |
| `MERIDIAN_CHNROUTE_BASE_URL` | 放 `china.txt`、`china6.txt` 的目录 URL（`http://` 或 `https://`） | gaoyifan/china-operator-ip 的 `ip-lists` 分支（GitHub raw） |
| `MERIDIAN_GEOSITE_BASE_URL` | 放 v2fly 分类文件（`cn`、`apple`……）的目录 URL | v2fly/domain-list-community 的 `master/data`（GitHub raw） |
| `MERIDIAN_FETCH_CONNECT_TIMEOUT` | 每次下载的连接超时（秒） | 10 |
| `MERIDIAN_FETCH_MAX_TIME` | 每次下载的总超时（秒） | 120 |
| `MERIDIAN_FETCH_RETRIES` | 失败后的重试次数 | 2 |

例如先在能访问 GitHub 的机器上把文件放到局域网里的 HTTP 目录，再：

```bash
sudo MERIDIAN_CHNROUTE_BASE_URL=http://<局域网主机>/lists /usr/local/sbin/meridian-update-chnroute.sh
sudo MERIDIAN_GEOSITE_BASE_URL=http://<局域网主机>/geosite /usr/local/sbin/meridian-update-geosite.sh
```

仓库不内置任何第三方镜像地址。注意每次 `meridian.service` 重载都会重建 `inet meridian`，chnroute 集合随之清空，要重跑 chnroute 脚本（见 [验收清单](verification.md) 的已知边界）。

SmartDNS 可以装在宿主机上，也可以在配置文件就位之后用 Compose 的 `dns` profile 拉起：

```bash
sudo docker compose -f deploy/docker-compose.yml --profile dns up -d
```

生成的网关配置只有三个监听：`bind [::]:53`、`bind-tcp [::]:53`、`bind-tls [::]:853`。在这个 SmartDNS 里 `[::]` 是双栈通配，再加一条 IPv4 专用的同端口监听（局域网地址或 `127.0.0.1`）会报 `Address already in use` 并启动失败。DoT 证书用全局指令 `bind-cert-file` / `bind-cert-key-file`（`bind-tls` 后面不接证书参数，写了会报 `unknown bind option`）。谁能查询由 `inet meridian` 的 input 链决定：53/853 只接受局域网前缀和本机回环（本机自己的查询，`dig @127.0.0.1` 或 `dig @192.168.100.88` 都走 lo），其余丢弃。开机时 Docker 拉起 SmartDNS 到 `meridian.service` 加载这张表之间，只靠这台机器位于 ROS 后面的局域网里。验收：`sudo bash deploy/verify-smartdns.sh`（网关地址不是 `192.168.100.88` 时设 `MERIDIAN_GW_ADDR`）。

上线前把 `pymumu/smartdns:latest` 钉成你核对过的摘要。然后按 [测试设备](test-device.md) 把一台电脑指过来，用 [验收清单](verification.md) 检查泄漏。清单区分自动化回归、隔离 Linux 集成证据和实机人工签收；`go test` 和面板「防泄露」页的通过项都不能当成「没有泄漏」的证据。

## 6. 二期和三期要手工做的事

这些不会从仓库自动变成可用的线上隧道：

- **Mesh（在面板里部署，不再手工放令牌）。** 部署 → 「Cloudflare Mesh 部署」：
  1. 在 Cloudflare 控制台建一个**账户级** API token，只给两项权限：`Cloudflare One Connectors Write`（创建 / 查询 / 删除 Mesh 节点、读取节点令牌）和 `Cloudflare One Networks Write`（发布 / 撤回 CIDR 路由）。账户 id 和 token 填进面板保存；token 只写不读，存放在数据目录 `mesh/cloudflare.json`（0600）。Cloudflare 文档要求第一个 API token 在控制台创建。
  2. 账户一侧的前置设置由你在 Cloudflare 控制台完成，面板不改（那需要更大的 `Zero Trust Write` 权限）：Zero Trust 组织；Mesh 节点的设备配置文件用 **MASQUE**（IPv6 路由要求）、Traffic and DNS 模式、Split Tunnels Include 包含 `100.96.0.0/12` **以及你要发布的路由**；设备互通与唯一 IP；Gateway 代理开启 TCP/UDP。
  3. 在拓扑里给每条 Mesh 边填「Mesh 发布路由」（出口端节点要通告的 CIDR；不接受默认路由），并保证枢纽已用新版本装机（预检会拒绝仍是 `default dev mmesh` 的旧脚本）。
  4. 粘贴 SSH 私钥（只用于本次请求，不保存），点「部署 Mesh」。面板依次：计划校验 → 远端预检 → 为每台主机创建 Cloudflare Mesh 节点 → 写入 compose / `meridian-mesh-up.sh` / `mesh.env`（0600）并启动 sidecar → 健康检查 → 发布路由 → 枢纽重新封装。任何一步失败都会撤回本次创建的东西；补偿没做完时面板会列出来，修好后点「撤回 / 重试补偿」。部署记录固定了每台主机实际连接的地址、端口、用户和首次连接时的 SSH 主机指纹，以及 Cloudflare 账户：撤回只连接这些主机并要求同一指纹（之后在拓扑里改地址或删节点不影响撤回，只需再次粘贴 SSH 私钥），只用原账户的凭据；撤回完成前面板拒绝切换到别的账户，同一账户可以更换 token。
  5. 结果「路由已发布」**不等于 Mesh 可用**。Mesh 数据面保持「未验证」，直到在隔离 Linux 主机上跑过 `sudo bash deploy/verify-mesh-veth.sh` 并做完 [验收清单](verification.md) 里的 Mesh 实机签收。

  家宽网关不运行 Mesh，Compose 里也没有 Mesh 服务。镜像是官方的 `cloudflare/mesh:latest`；要钉住摘要，在拓扑的 `mesh_image` 里写。没有路由时 sidecar 会把这一跳留在黑洞，不会改从 VPS 的默认路由出去。
- **解锁容器。** 在出口上安装 Docker，并 `docker pull lmc999/regioncheck:latest`（或你写进 `regioncheck_image` 的那个标签）。面板不下载、不内置这个 AGPL 程序。探测脚本是 `/usr/local/sbin/meridian-unlock-probe.sh`，它会覆盖镜像入口并带上 `-R 66 -M 4` 和 `-M 6`。要自动把结果送回面板，把 `/etc/meridian/unlock-report.env.example` 复制成同目录的 `unlock-report.env`，权限 `0600`，只填 `MERIDIAN_PANEL_TOKEN`。面板自己也能探测：「解锁 → 面板探测」的「立即测试」和面板每 6 小时的定时都经网关上的 `meridian-host`（`/v1/probe`）从所选出口发出，不需要也不再读取 `MERIDIAN_UNLOCK_EXEC`。`meridian-host` 不可用、出口上也没有报告时，面板不会编造探测结果，路由保持不动。
- **纯 IPv6 端点。** 把示例里的 `2001:db8::60`、`2001:db8::70` 换成真实地址之前，不要下发。枢纽仍然没有 IPv6，不要把纯 v6 出口的端点写到枢纽上。
- **NAT64。** 占位文件在枢纽的 `/etc/meridian/nat64.reserved.conf`。这一期不要手写一条 NAT64 路由来「补上」，除非你知道它不会盖住现有 v4 路径。
- **同网段验收。** 下发后在网关执行 `sudo /usr/local/sbin/meridian-verify.sh`，把它打印的证据目录存档。缺 nft 或缺 `inet meridian` / `inet meridian_guard` 任何一张表都会失败；最后一行 `meridian-verify-local-ok` 只代表本机检查通过，DNS 泄漏、WebRTC、断隧道和抓包仍显示 `PENDING-HUMAN`，要在测试机上人工签收。ROS 上的 fd00 黑洞只查看、不修改：手工执行只读的 `/ipv6 route print`，或加 `MERIDIAN_ROS_SSH=user@192.168.100.1` 让脚本执行并保存输出。

## 7. 和 ROS 同网段时

- `rp_filter` 必须是 loose（2）。国内回程可能由 ROS 直接交给客户端。
- 关闭本机发送 ICMP 重定向。ROS 自己仍可能对客户端发重定向，这不在这台机器的控制范围内。
- 不要做代理 ARP，不要占用 `.1`。

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

- 写入并应用 `/etc/sysctl.d/99-meridian.conf`（开机时转发保持关闭、`rp_filter=2`、关闭 IPv4 发送重定向、局域网口 `accept_ra=2`）；转发由 `meridian-up.sh` 在防火墙和兜底表加载之后打开，脚本结束时 IPv4 / IPv6 转发都是关的
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

#### 从改版前的面板升级时数据怎么变

新面板第一次启动时按顺序做三件事，都可以重复执行，日志里只有数量和 ID（`docker compose logs meridian`）：

1. **未完成的宿主事务**先补偿或完成（和平时重启一样）。
2. **凭据迁移**：数据卷里旧的 `mesh/cloudflare.json` 变成一个 Cloudflare 账户（ID `cf-mesh`，并选为 Mesh 账户），令牌移进新的 `meridian-secrets` 卷，旧文件删除；拓扑节点上的 `ssh_host` / `ssh_port` / `ssh_user` 变成「服务器」（ID `srv-<节点 ID>`），节点只留 `server_id`。旧版从不保存 SSH 私钥，所以这些服务器**没有凭据**：到「密钥」页添加，再回「服务器」页选上。Mesh 部署记录里固定过的主机指纹会作为「已确认」导入；部署记录从 schema 2 升级到 3。示例里 `.invalid` 结尾的地址不迁移。
3. **地区组迁移**：旧的出口池和规则的 `target_pool` / `mode` 变成地区组，默认境外流量用 `hk` 组；迁移前后的出口选择相同（细节见 [架构](architecture.md)「地区组」）。

迁移只改面板的数据，宿主上的数据面不动。之后在「部署」页看差分并「安装到本机」一次，新的守卫范围、地区组标记和（启用时的）远程接入才进入数据面。这条完整升级路径有一个自动化测试（`internal/api/upgrade_test.go` 的 `TestUpgradeFromPreRedesignDataDir`），它用的是旧版仓库示例，不是真实网关的数据。

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

第二个命名卷 `meridian-secrets`（容器里 `/var/lib/meridian-secrets`，`MERIDIAN_SECRETS_DIR`）放服务器、SSH 凭据（密码、私钥、口令）、Cloudflare 令牌，以及远程接入的网关私钥和预共享密钥。它**只靠权限保护**：目录 0700、文件 0600，权限更宽的文件面板拒绝使用；**没有静态加密**，能以 root 读宿主或 Docker 卷的人就能读到这些秘密。它不进数据卷的快照、日志和 API 响应；备份时要单独、加密地备份这个卷，并且不要把它改成宿主绑定目录或放进 git。不用 Docker 时默认在 `MERIDIAN_DATA/secrets`。

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

**顺序：先远端，后网关。** 第一次装机和以后每次改拓扑，都先给受影响的远端节点（出口、枢纽、阿里云）下发，再安装网关。原因之一是地区组的解析：网关把可切换地区组的查询发往组的解析地址（`fd66::53:0/112` 里的一个），只有已经下发了这一版配置的出口才会应答；网关先装的话，组内的名字在出口更新之前解析不了——不会改问国内解析器或别的出口（见 [架构](architecture.md)「地区组的解析」）。编译结果的 `APPLY_ORDER.txt` 也写了这个顺序。

远程节点的装机脚本可以先演练（`POST /api/provision` 带 `dry_run: true`，不需要服务器，脚本里只有占位符）。真正装机经下面「服务器、密钥与 Cloudflare」里配好的服务器执行，请求里只有节点 ID，不再粘贴私钥。响应里不会出现新生成的 WireGuard 私钥明文。

wstunnel 需要单独安装到 `/usr/local/bin/wstunnel`，版本请钉死你核对过的 [erebe/wstunnel](https://github.com/erebe/wstunnel/releases) release。脚本不会从网络上直接下载二进制。

## 5. 服务器、密钥与 Cloudflare

面板登录远端机器、调用 Cloudflare 只用面板里保存的对象，请求里不再带私钥、密码或「信任新主机」这类开关（旧字段 `private_key_pem`、`trust_new_host`、`ssh_*` 一律 400 `field_removed`）。

1. **密钥**（侧边栏「资源 → 密钥」）：添加 SSH 凭据——密码，或导入私钥（可带口令），或让面板生成一把并把显示的 `authorized_keys` 公钥放到远端。秘密只写不读，之后只显示类型、指纹和是否带口令。
2. **服务器**（「资源 → 服务器」）：填地址、端口、用户，选认证方式和凭据；在「拓扑」里把远端节点关联到这台服务器（每台服务器只对应一个节点，网关节点不关联服务器）。
3. **确认主机指纹**：点「发现指纹」只做密钥交换、不认证；把显示的 SHA256 指纹和你在远端控制台上看到的（`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`）核对一致，再点「确认」。之后指纹变了连接会在认证之前被拒绝（`host_key_mismatch`），原指纹保留，直到你确认新的。
4. **连接测试**：只登录并运行固定命令读架构、内核和系统版本。通过后服务器显示「就绪」，装机和 Mesh 部署都要求这个状态。轮换凭据、改地址或用户会清掉测试结果。
5. **Cloudflare**（「资源 → Cloudflare」）：添加账户（account id 和账户级 API token，只写不读），点「检查权限」。检查只调用只读接口：证明令牌有效、属于这个账户、能读 Mesh 节点和路由；**不能证明写权限**（读取令牌自身的权限清单需要额外权限，面板不要求），缺写权限会在部署的「创建节点」阶段失败并被补偿。所需权限见下面「Mesh」。

## 6. 名单

名单源（国内镜像 / 海外 / 全自动）在面板里选，保存在拓扑设置 `list_source`；「立即更新」经宿主上的 `meridian-host` 执行（见 [架构](architecture.md)「名单源」）。配置安装好、nftables 表已经存在之后，也可以在网关上直接运行同一个动作：

```bash
sudo /usr/local/sbin/meridian-update-chnroute.sh
sudo /usr/local/sbin/meridian-update-geosite.sh
sudo MERIDIAN_LIST_SOURCE=overseas /usr/local/sbin/meridian-update-geosite.sh   # 只这一次换策略
```

两个脚本只调用 `meridian lists-update`，不自己下载；需要 `meridian-host` 在运行。更新后 SmartDNS 由 `meridian-host` 重启。退出码：0 全部更新，1 一个都没更新（或被拒绝），2 部分名单保留了旧版本。

**第一次安装后必须更新一次名单。** 编译出的规则里 `chnroute` / `chnroute6` 集合是空的，`geosite/cn.txt` 只是为了让 SmartDNS 能启动而建的空文件；名单更新之前，国内地址和域名都按境外处理（走默认地区组，不是泄漏，但分流不对）。`meridian-verify.sh` 因此在这些集合或 `cn.txt` 为空时报 `FAIL chnroute_loaded` / `FAIL geosite_cn`，并在 `INFO list …` 行里列出宿主记录的每个名单的来源、条数和时间。在面板「网络 → 名单」看同样的记录。

- 下载失败、超时、内容为空或不像名单（比如一张 HTML 错误页）时，**不替换**已有的名单文件，也**不清空** chnroute 集合（两个地址族的清空和写入在同一个 nft 事务里）
- geosite 的 `include:` 会递归展开，`cn` 不再是空的
- 结果（每个名单的来源、时间、条数、错误）在 `/var/lib/meridian/lists/status.json`

国内源是 jsDelivr，海外源是 GitHub raw。要换成局域网里的副本，给 `meridian-host.service` 加 drop-in（只替换国内源）：

```ini
# systemctl edit meridian-host.service
[Service]
Environment=MERIDIAN_GEOSITE_BASE_URL=http://<局域网主机>/geosite
Environment=MERIDIAN_CHNROUTE_BASE_URL=http://<局域网主机>/lists
```

旧的 `MERIDIAN_FETCH_*` 变量不再使用：超时和重试固定在程序里。重载 `meridian.service` 后，`meridian-up.sh` 会把上次成功加载的 chnroute 一起装回去。

SmartDNS 可以装在宿主机上，也可以在配置文件就位之后用 Compose 的 `dns` profile 拉起：

```bash
sudo docker compose -f deploy/docker-compose.yml --profile dns up -d
```

生成的网关配置只有三个监听：`bind [::]:53`、`bind-tcp [::]:53`、`bind-tls [::]:853`。在这个 SmartDNS 里 `[::]` 是双栈通配，再加一条 IPv4 专用的同端口监听（局域网地址或 `127.0.0.1`）会报 `Address already in use` 并启动失败。DoT 证书用全局指令 `bind-cert-file` / `bind-cert-key-file`（`bind-tls` 后面不接证书参数，写了会报 `unknown bind option`）。谁能查询由 `inet meridian` 的 input 链决定：53/853 只接受局域网前缀和本机回环（本机自己的查询，`dig @127.0.0.1` 或 `dig @192.168.100.88` 都走 lo），其余丢弃。开机时 Docker 拉起 SmartDNS 到 `meridian.service` 加载这张表之间，只靠这台机器位于 ROS 后面的局域网里。验收：`sudo bash deploy/verify-smartdns.sh`（网关地址不是 `192.168.100.88` 时设 `MERIDIAN_GW_ADDR`）。

上线前把 `pymumu/smartdns:latest` 钉成你核对过的摘要。然后按 [测试设备](test-device.md) 把一台电脑指过来，用 [验收清单](verification.md) 检查泄漏。清单区分自动化回归、隔离 Linux 集成证据和实机人工签收；`go test` 和面板「防泄露」页的通过项都不能当成「没有泄漏」的证据。

## 7. 二期和三期要手工做的事

这些不会从仓库自动变成可用的线上隧道：

- **Mesh（在面板「资源 → Cloudflare」里部署，不再手工放令牌）。**
  1. 在 Cloudflare 控制台建一个**账户级** API token，只给两项权限：`Cloudflare One Connectors Write`（创建 / 查询 / 删除 Mesh 节点、读取节点令牌）和 `Cloudflare One Networks Write`（发布 / 撤回 CIDR 路由）。在 Cloudflare 页添加账户（token 只写不读，存放在 `meridian-secrets` 卷里，0600），点「检查权限」，再把它选为 Mesh 账户。Cloudflare 文档要求第一个 API token 在控制台创建。
  2. 账户一侧的前置设置由你在 Cloudflare 控制台完成，面板不改（那需要更大的 `Zero Trust Write` 权限）：Zero Trust 组织；Mesh 节点的设备配置文件用 **MASQUE**（IPv6 路由要求）、Traffic and DNS 模式、Split Tunnels Include 包含 `100.96.0.0/12` **以及你要发布的路由**；设备互通与唯一 IP；Gateway 代理开启 TCP/UDP。
  3. 在拓扑里给每条 Mesh 边填「Mesh 发布路由」（出口端节点要通告的 CIDR；不接受默认路由），并保证枢纽已用新版本装机（预检会拒绝仍是 `default dev mmesh` 的旧脚本）。
  4. 确认计划里每个节点都关联了「就绪」的服务器（Cloudflare 页的部署卡片会列出缺凭据、缺指纹或缺连接测试的节点，有任何一个就拒绝部署），点「部署 Mesh」。面板依次：计划校验 → 远端预检 → 为每台主机创建 Cloudflare Mesh 节点 → 写入 compose / `meridian-mesh-up.sh` / `mesh.env`（0600）并启动 sidecar → 健康检查 → 发布路由 → 枢纽重新封装。任何一步失败都会撤回本次创建的东西；补偿没做完时面板会列出来，修好后点「撤回 / 重试补偿」。部署记录固定了每台主机的服务器 ID、凭据 ID、地址、端口、用户和已确认的主机指纹，以及 Cloudflare 账户：撤回只连接这些主机并要求同一指纹（之后在拓扑里删节点不影响撤回；被固定的服务器和凭据在撤回完成前不能删除或改指向，凭据可以原地轮换），只用原账户的凭据；撤回完成前面板拒绝切换到别的账户，同一账户可以更换 token。
  5. 结果「路由已发布」**不等于 Mesh 可用**。Mesh 数据面保持「未验证」，直到在隔离 Linux 主机上跑过 `sudo bash deploy/verify-mesh-veth.sh` 并做完 [验收清单](verification.md) 里的 Mesh 实机签收。

  家宽网关不运行 Mesh，Compose 里也没有 Mesh 服务。镜像是官方的 `cloudflare/mesh:latest`；要钉住摘要，在拓扑的 `mesh_image` 里写。没有路由时 sidecar 会把这一跳留在黑洞，不会改从 VPS 的默认路由出去。
- **解锁容器。** 在出口上安装 Docker，并 `docker pull lmc999/regioncheck:latest`（或你写进 `regioncheck_image` 的那个标签）。面板不下载、不内置这个 AGPL 程序。探测脚本是 `/usr/local/sbin/meridian-unlock-probe.sh`，它会覆盖镜像入口并带上 `-R 66 -M 4` 和 `-M 6`。要自动把结果送回面板，把 `/etc/meridian/unlock-report.env.example` 复制成同目录的 `unlock-report.env`，权限 `0600`，只填 `MERIDIAN_PANEL_TOKEN`。面板自己也能探测：「解锁 → 面板探测」的「立即测试」和面板每 6 小时的定时都经网关上的 `meridian-host`（`/v1/probe`）从所选出口发出，不需要也不再读取 `MERIDIAN_UNLOCK_EXEC`。`meridian-host` 不可用、出口上也没有报告时，面板不会编造探测结果，路由保持不动。
- **纯 IPv6 端点。** 把示例里的 `2001:db8::60`、`2001:db8::70` 换成真实地址之前，不要下发。枢纽仍然没有 IPv6，不要把纯 v6 出口的端点写到枢纽上。
- **NAT64。** 占位文件在枢纽的 `/etc/meridian/nat64.reserved.conf`。这一期不要手写一条 NAT64 路由来「补上」，除非你知道它不会盖住现有 v4 路径。
- **远程接入（可选）。** 见 [远程接入](remote-access.md)：面板只管网关这一侧，路由器上的 UDP 端口转发由你自己做，手机实测要人工签收。
- **同网段验收。** 下发后在网关执行 `sudo /usr/local/sbin/meridian-verify.sh`，把它打印的证据目录存档。缺 nft 或缺 `inet meridian` / `inet meridian_guard` 任何一张表都会失败；它还按宿主上实际加载的状态核对每个出口和地区组标记的策略路由、兜底表的标记范围和入口、开机兜底文件、国内名单是否为空、53 端口，以及远程接入（关闭时确认没有 `mra`）。最后一行 `meridian-verify-local-ok` 只代表本机检查通过，DNS 泄漏、WebRTC、断隧道、抓包和远程接入的手机实测仍显示 `PENDING-HUMAN`，要人工签收。ROS 上的 fd00 黑洞只查看、不修改：手工执行只读的 `/ipv6 route print`，或加 `MERIDIAN_ROS_SSH=user@192.168.100.1` 让脚本执行并保存输出。

## 8. 和 ROS 同网段时

- `rp_filter` 必须是 loose（2）。国内回程可能由 ROS 直接交给客户端。
- 关闭本机发送 ICMP 重定向。ROS 自己仍可能对客户端发重定向，这不在这台机器的控制范围内。
- 不要做代理 ARP，不要占用 `.1`。

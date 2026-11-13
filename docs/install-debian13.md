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
- 构建面板镜像，把同一个 `meridian` 二进制复制到 `/usr/local/bin`，生成 `/etc/meridian-host/agent.token`（0600），启动 `meridian-host.service`。面板容器只能通过它的 root-only socket 请求固定动作（激活、健康检查、回滚、撤回，以及只读的安装前预检、名单更新、解锁探测和远程接入状态），没有 `NET_ADMIN`、`/dev/net/tun` 或 systemd。`meridian-host` 没运行时，面板的「安装到本机」会直接报错，不会假装成功
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

无论哪种模式，脚本开始时为 0 的转发项在结束时仍是 0。

**`meridian-host` 和面板一起升级。** 这一版的「安装到网关」在写任何文件之前要先经 `meridian-host` 的只读动作 `/v1/preflight` 做安装前预检；旧版 `meridian-host` 没有这个动作，新面板配旧 agent 时安装会以 503 `host_unavailable` 拒绝（什么都不写）。`install.sh` 的升级模式会同时换掉 `/usr/local/bin/meridian` 并重启 `meridian-host`，所以按本节先跑 `install.sh`、再重建面板容器即可；只重建容器、不跑 `install.sh` 是不够的。

**受管 sysctl 文件。** 升级模式不重写 `99-meridian.conf`（只把「开机即打开转发」的行改成 0），所以升级之后、下一次面板安装之前，文件里可能还留着 `install.sh` 或旧版本写的行。下一次「安装到网关」会**整份重写**这个文件和 `/etc/meridian/forwarding.conf`（每次安装都是，不管内容变没变），`meridian-up.sh` 应用其中除开机转发两行之外的每一行并在日志里写一行 `meridian-sysctl: applied N, skipped M`。安装结果里有一块「内核参数」：写入了哪些键、每个键安装后从运行中的内核读回的值是否一致（不一致或内核没有这个键的会同时列为警告），以及**旧文件里有、新文件不再设置的键**——文件里它们已经没有了，但运行中的内核保留原值直到重启，Meridian 不知道原来的默认值，不去改它们。这块结果只是读回内核值，不是泄漏结论；它和下面所有新功能一样**还没有在真实网关上执行过**。

之后用新镜像重建面板容器（不影响数据面）：

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

**开机时局域网地址还没就绪。** 局域网口用 DHCP（`allow-hotplug`）时，Docker 会在拿到租约之前就启动面板容器，这时绑定 `MERIDIAN_BIND` 会得到 `cannot assign requested address`。面板不再靠容器反复崩溃重启来等：它每秒重试一次，最多等 `MERIDIAN_BIND_WAIT`（Compose 里是 `180s`，默认 3 分钟），开始时和之后每 10 秒在日志里写一行 `meridian-bind-waiting: <地址> is not assigned to any interface yet …`，地址出现后写 `meridian-bind-ready …` 并开始服务；等满仍没有就以 `meridian-bind-not-ready: …` 退出（说明要检查局域网口、租约或 `MERIDIAN_BIND`），此时由 Compose 的 `restart: unless-stopped` 再拉起一次。其他绑定错误（端口被占用等）立即退出，不等待。它永远不会改绑 `0.0.0.0`。查看：`sudo docker compose -f deploy/docker-compose.yml logs meridian`。这个等待只在自动化测试里验证过（模拟的 `EADDRNOTAVAIL` 和本机未分配的文档地址），**还没有在真实网关开机时观察过**。

第二个命名卷 `meridian-secrets`（容器里 `/var/lib/meridian-secrets`，`MERIDIAN_SECRETS_DIR`）放服务器、SSH 凭据（密码、私钥、口令）、Cloudflare 令牌，以及远程接入的网关私钥和预共享密钥。它**只靠权限保护**：目录 0700、文件 0600，权限更宽的文件面板拒绝使用；**没有静态加密**，能以 root 读宿主或 Docker 卷的人就能读到这些秘密。它不进数据卷的快照、日志和 API 响应；备份时要单独、加密地备份这个卷，并且不要把它改成宿主绑定目录或放进 git。不用 Docker 时默认在 `MERIDIAN_DATA/secrets`。

Debian 13 上请用 `docker compose`（来自 `docker-compose-v2`）。只有旧的 `docker-compose` 命令时，用那一个；这份 Compose 文件需要 v2 的 `profiles`。

## 4. 换成真实端点再下发

仓库和面板里的初始拓扑是文档地址：

- `203.0.113.0/24`、`198.51.100.0/24`：出口和中继的公网 IPv4
- `2001:db8:100::/64`：局域网 IPv6 前缀占位，改成运营商实际委派的 /64
- `fe80::1`：改成 ROS bridge 上的真实链路本地地址
- `example.invalid`：管理域名

**WSS 不需要证书文件、域名或 ACME。** 每条 WSS 链路的升级路径前缀（192 位随机数）和每个 WSS 监听的自签证书（ECDSA P-256，365 天，名字是随机的 `….invalid`）都由面板生成，存进面板的凭据存储，只在「安装到本机」和远端「下发」时写进两端的 `/etc/meridian/wss/`（目录 0700，路径和私钥文件 0600）。客户端只信任这一张证书并校验这个名字（wstunnel 11.1.0 没有指纹固定选项，用的是 `SSL_CERT_FILE` 唯一信任根 + `--tls-verify-certificate` + `--tls-sni-override`）。「部署」页的「WSS 承载」显示每个监听的证书指纹、到期时间、各端阶段和下一步，并提供「重新生成路径」「重新生成证书」；轮换时两端交替重新下发，每次这一端的 WSS 腿中断几秒，只更新了一端时隧道仍通。证书到期前 30 天面板自动生成新证书并告警，但不会自己去改主机：要按下一步下发。

**从旧版升级**：拓扑里的 `wss_path_prefix`、`tls_cert_path`、`tls_key_path` 在面板启动时被移出，换成随机路径和面板的证书（`/etc/meridian/tls/` 里你自己放的证书不再使用，也不会被删除）。以前装过的监听进入「迁移中」：先重新下发服务端（同时接受旧路径和新路径，旧客户端不受影响），再重新下发每个客户端，最后再下发一次服务端去掉旧路径。细节见 [架构](architecture.md)「WSS 承载：随机路径与自签证书」。这些都**没有在真实主机上执行过**。

私钥由装机时生成，API 返回给浏览器时会打成 `***`。不要把私钥、面板数据目录或 `/var/lib/meridian` 提交进 git。

下发分三步：

1. **校验路径**。缺 IX（或缺「IX 即主枢纽」的主枢纽）、备用枢纽没接好、出口少了到某个枢纽的隧道、Mesh 绕过、NAT 方向错误、Netflix 没走家宽、网关节点的 `lan_interface` 和 `settings.lan_interface` 不一致，都会报错并拒绝保存。
2. **演练**。只产生差分，不写文件。
3. **写入数据目录**，确认后再 **安装到本机**。安装只会覆盖和删除受管清单里属于 Meridian 的 WireGuard、nftables、sysctl、SmartDNS、unit 和脚本，nft 以单个事务替换；随后经 `meridian-host` 启动服务并做健康检查，任一步失败即停止并补偿回安装前。**回滚（含宿主网络）** 把宿主和数据目录一起恢复到上一份，删除新版本引入的文件、接口和服务。实机验收：`sudo bash deploy/verify-host-exec.sh`。

「安装到本机」还要求本机每条 WireGuard 隧道对端节点都有可用的公钥（44 字符 base64）。初始拓扑里对端是占位符：这时安装直接以 422 拒绝并列出缺公钥的节点，不生成网关密钥、不写宿主文件、不动快照；编译、预览、演练和差分照常可用。先给对端生成密钥（「生成脚本」/ provision 的 `generate_keys`）或把公钥填进拓扑。

**顺序：先远端，后网关。** 第一次装机和以后每次改拓扑，都先给受影响的远端节点（出口、枢纽、阿里云）下发，再安装网关。原因之一是地区组的解析：网关把可切换地区组的查询发往组的解析地址（`fd66::53:0/112` 里的一个），只有已经下发了这一版配置的出口才会应答；网关先装的话，组内的名字在出口更新之前解析不了——不会改问国内解析器或别的出口（见 [架构](architecture.md)「地区组的解析」）。编译结果的 `APPLY_ORDER.txt` 也写了这个顺序。

远程节点的装机脚本可以先演练（`POST /api/provision` 带 `dry_run: true`，不需要服务器，脚本里只有占位符）。真正装机经下面「服务器、密钥与 Cloudflare」里配好的服务器执行，请求里只有节点 ID，不再粘贴私钥。响应里不会出现新生成的 WireGuard 私钥明文。

**装机前预检。** 在「部署 → 远端节点」点「生成密钥并下发」或「下发」，面板先经已固定指纹的 SSH 运行一份固定的**只读**预检脚本，列出：目标（服务器、地址、端口、固定指纹、凭据）、要做的变更（新建或替换的文件、接口、监听端口、路由、规则、nft 表、服务、软件包、会打开的转发）和与主机上已有东西的冲突（按「阻断 / 警告 / 信息」分组，每条都写了发现了什么、怎么处理）。有阻断项时「执行」按钮不可用，面板这一版**不能跳过**阻断项，也**不会替你改**别的服务（例如 Docker 的 `FORWARD DROP`）。确认后执行，面板在执行前还会在同一台主机上再预检一次，结果变了就拒绝并显示新结果。安装到网关同理：「安装前预检」经 `meridian-host` 的只读动作做同样的检查，第一次安装前必须先做。

预检会拒绝的典型情况：不是支持的系统（Debian 12 / 13 x86_64、Ubuntu 20.04 aarch64 以外的发行版、版本或架构组合）、不是 root、没有 systemd；FORWARD 策略是 DROP（通常是 Docker）；接口名、监听端口（WireGuard、WSS 443、wstunnel 本地端口、解析器的隧道地址:53）、隧道地址或路由与已有的重叠；路由表、防火墙标记、`inet meridian` 已被别人用；要写的路径上有不属于 Meridian 的文件（例如另一份 `/etc/smartdns/smartdns.conf`）；主机已被另一个节点或另一个面板装过；面板没有这台主机架构的已校验 wstunnel / SmartDNS（`wstunnel_missing` / `smartdns_unavailable`，面板镜像缺文件或摘要不符时）；要跑解析器而可用内存低于预算（`memory_budget`）。完整列表、判定方法和它**不检查**的东西见 [架构](architecture.md)「装机前预检」。

第一次装机失败时，脚本会补偿：撤掉这次新建的文件、接口、nft 表、规则、路由和服务，恢复被替换的文件和 sysctl；装上的软件包保留并列出。撤不掉的会逐项列出，也写在服务器的 `/var/lib/meridian/node/journal`；在处理之前，下一次预检会阻止再装。遇到「上一次装机没有正常结束」（`previous_run_incomplete`）时，在部署页对这个节点点「恢复中断的装机」：面板先只读列出这次运行做过的事，你确认后按服务器上的工作目录跑同一套补偿（见第 9 节）。工作目录不在了时面板会拒绝并说明，这时才需要登录服务器按 journal 手工处理。

**旧版本装过的远端节点**（没有 `/var/lib/meridian/node/manifest`）会被预检判为 `legacy_install` 而拒绝：面板无法确认这些文件属于哪个节点，也无法准确补偿。在部署页对这个节点做「旧版清理」（第 9 节）：只处理固定路径上带 Meridian 标记的文件和它们声明的接口、服务、nft 表、路由表，先列清单、你确认后才删。也可以手工停用并移走旧文件。之后按第一次装机处理。

**登录方式不被接受**时，连接测试和预检会直接说明是「服务器不提供这种登录方式」还是「这份凭据被拒」，并列出服务器实际提供的登录方式。只有服务器提供公钥登录时，才建议改用密钥并给出可以复制的公钥（面板保存的密钥凭据的公钥，不含任何秘密）和把它加进 `authorized_keys` 的步骤；只收密码的服务器（例如只能经端口转发到达、只开密码登录的那台）用它的密码凭据就能完成全部操作，面板只会提示改用密码凭据。

**不用再手装 wstunnel 和 SmartDNS。** 面板镜像里带着固定版本的 wstunnel 11.1.0 和 SmartDNS 1.2026.08.05-0921（Release48.4），各有 x86_64 和 aarch64 两份，版本和 SHA-256 写死在 `internal/artifacts/artifacts.lock`。装机时面板按预检看到的架构，经同一条 SSH 连接把需要的那份传到服务器（主机上已经是同一摘要就不传），服务器在激活任何东西之前再核对一次摘要，不符就拒绝、什么都不改。它们装在 Meridian 自己的路径 `/usr/local/sbin/meridian-wstunnel`、`/usr/local/sbin/meridian-smartdns`，出口解析器由单元 `meridian-smartdns.service` 运行，只绑隧道地址；服务器上原有的 `/usr/local/bin/wstunnel` 或发行版的 smartdns 不会被覆盖或删除，远端节点也不再从 apt 装 smartdns。网关的 WSS 客户端用的 wstunnel 也由「安装到网关」写到网关的 `/usr/local/sbin/meridian-wstunnel`。目标主机不需要访问任何境外下载源。

**构建镜像需要联网一次**：`docker buildx build --platform linux/amd64 -f deploy/Dockerfile …` 的 `artifacts` 阶段要访问 `deb.debian.org`（装 curl）和 `github.com` / `objects.githubusercontent.com`（下载上面四个文件），下载后核对 SHA-256，不符则构建失败。构建机连不上 GitHub 时，把四个上游文件（`wstunnel_11.1.0_linux_amd64.tar.gz`、`wstunnel_11.1.0_linux_arm64.tar.gz`、`smartdns-x86_64`、`smartdns-aarch64`，即锁文件里 URL 的最后一段）放进 `deploy/artifacts/` 再构建，同样核对摘要。部署页「面板下发的二进制」显示面板持有的副本是否通过校验。

**支持的远端系统**：Debian 12 / 13（x86_64）和 Ubuntu 20.04（aarch64，内核 5.15）。缺的 wireguard-tools、nftables 会列进预检的安装计划并经 apt 安装（不装推荐包）；Ubuntu 20.04 上不会切换 iptables 的 legacy 后端，也不碰已有的 legacy 规则（两者如何共存、预检看了什么没看什么，见[架构](architecture.md)「与 iptables-legacy 共存」）。其他系统、架构和 5.6 以前的内核被拒绝并说明原因。要在本机跑出口解析器的节点，可用内存低于预算（装机余量 48 MB + SmartDNS 48 MB，有 WSS 再加 32 MB）时预检阻断，不会去掉解析器或改用别的解析器。

以上预检、二进制下发、复核和补偿只在仓库的自动化测试里跑过（进程内 SSH 服务器、假宿主代理、带桩命令的本机沙箱、假二进制），**还没有在真实服务器上执行过**；固定版本的 wstunnel / SmartDNS 也没有在 Ubuntu 20.04 arm64 或 Debian 12 上实际运行过。

## 5. 服务器、密钥与 Cloudflare

面板登录远端机器、调用 Cloudflare 只用面板里保存的对象，请求里不再带私钥、密码或「信任新主机」这类开关（旧字段 `private_key_pem`、`trust_new_host`、`ssh_*` 一律 400 `field_removed`）。

1. **密钥**（侧边栏「资源 → 密钥」）：添加 SSH 凭据——密码，或导入私钥（可带口令），或让面板生成一把并把显示的 `authorized_keys` 公钥放到远端。秘密只写不读，之后只显示类型、指纹和是否带口令。
2. **服务器**（「资源 → 服务器」）：填地址、端口、用户，选认证方式和凭据；在「拓扑」里把远端节点关联到这台服务器（每台服务器只对应一个节点，网关节点不关联服务器）。
3. **确认主机指纹**：点「发现指纹」只做密钥交换、不认证；把显示的 SHA256 指纹和你在远端控制台上看到的（`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`）核对一致，再点「确认」。之后指纹变了连接会在认证之前被拒绝（`host_key_mismatch`），原指纹保留，直到你确认新的。
4. **连接测试**：只登录并运行固定命令读架构、内核和系统版本。通过后服务器显示「就绪」。轮换凭据、改地址或用户会清掉测试结果。装机、预检和 Mesh 部署**强制要求**的是「可操作」（已确认指纹、已选凭据）；连接测试是面板建议的一步（概览「下一步」和服务器列表会提示），本身不是关卡——没做测试直接预检，预检同样要登录，登录不了会在那一步失败并说明原因。
5. **Cloudflare**（「资源 → Cloudflare」）：添加账户（account id 和账户级 API token，只写不读），点「检查权限」。检查只调用只读接口：证明令牌有效、属于这个账户、能读 Mesh 节点和路由；**不能证明写权限**（读取令牌自身的权限清单需要额外权限，面板不要求），缺写权限会在部署的「创建节点」阶段失败并被补偿。所需权限见下面「Mesh」。

### 第一次部署：按面板的顺序

下面是面板自己的顺序，每一步都会拒绝在前一步之前做（括号里是被拒时的错误码）。整条顺序有一个端到端的自动化测试（`internal/api/e2e_flow_test.go` 的 `TestPanelFlowEndToEnd`：进程内 SSH 服务器充当远端节点，真实的 `meridian-host` 代理代码跑在 Unix socket 上、命令执行是模拟的），**没有在真实服务器或网关上走过**。

1. **密钥**：添加一份 SSH 凭据（密码、导入的私钥或面板生成的密钥）。服务器不能引用不存在的凭据。
2. **服务器**：地址、端口、用户、认证方式和凭据。
3. **确认主机指纹**：「发现指纹」→ 核对 → 「确认」。确认之前连接测试、预检和装机都被拒（409 `host_key_untrusted`），面板不会登录；提交一个不是刚发现的指纹不会被确认。
4. **连接测试**：通过后服务器显示「就绪」（建议步骤，不是关卡，见上面第 4 点）。
5. **拓扑**：在「拓扑」里为远端节点选择这台服务器。没选之前预检被拒（409 `no_server`）。
6. **远端预检**：「部署 → 远端节点 → 生成密钥并下发」先跑只读预检并显示结果。第一次装机没有审阅过的预检时被拒（409 `preflight_required`），不生成密钥、不运行脚本；预检过期、被替换（`preflight_stale`）、之后拓扑或目标身份变了（`bundle_changed`、`target_changed`）、有阻断项（`preflight_blocked`）或执行前复核出了新问题（`preflight_changed`）都拒绝。
7. **第一次装机**：确认后执行；成功时节点有了公钥，部署记录固定这台服务器、凭据和指纹。所有远端节点按 `APPLY_ORDER.txt` 先装。
8. **网关预检**：「部署 → 安装前预检」，经 `meridian-host` 的 `/v1/preflight`。第一次安装（以及撤回之后重新安装）没有审阅过的网关预检时被拒（409 `preflight_required`），网关上什么都不写、不激活；预检之后改了拓扑，这份预检就不再对应要安装的内容（409 `bundle_changed`），重新预检。网关的直接 WireGuard 对端没有公钥时安装被拒（422 `peer_keys_missing`）。
9. **安装到网关**：持久事务；结果里有宿主步骤、资源差异和「内核参数」一块（见上面「升级」）。之后状态是「与网关一致」。
10. **名单 → 立即更新** 一次，再在网关上跑 `meridian-verify.sh`，然后按 [验收清单](verification.md) 做人工签收项。

撤回和恢复见第 9 节。

### IX 作为主枢纽、另加备用枢纽

IX 本身是一台能登录的服务器、并且由它连各出口时，不再画不可管的 `ix` 节点：

1. 「服务器」里为 IX 建一台服务器，地址和端口填**能到达它 SSH 的地方**（例如某台中继上转发到 IX 22 端口的那个端口），只接受密码时用密码凭据。经转发到达时 sshd 会按转发器地址限速，面板识别为 `ssh_rate_limited` 并给出稍后重试的时间。
2. 「拓扑」里把枢纽节点设为「主枢纽」，打开「IX 即主枢纽」，填「国内入口地址」（中继拨入的地址，`ingress_v4`）、可选的「国内入口接口」，`endpoint_v4` 填香港出口地址，`wan_interface` 填香港一侧带默认路由的网卡，并为它选择上一步的服务器。中继 → IX 用 `direct_wg`（不是 `dedicated_line`）。
3. 备用枢纽：再加一个枢纽节点，设为「备用枢纽」，`endpoint_v4` 是它的公网地址，`wss_listen_port` 选一个没被占用的端口；画一条家宽网关 → 备用枢纽的 `ix_replacement_wss`（待命）链路。每个出口都要和两个枢纽各连一条 WireGuard。
4. 下发顺序不变：先出口，再两个枢纽，再中继，最后网关（`APPLY_ORDER.txt`）。IX 的预检会核对国内入口地址在不在主机上、在不在写的网卡上（见[架构](architecture.md)「WAN 接口」）。

网关在主链路（网关 → 中继 → IX）端到端不通时自动改走备用枢纽，恢复后自动切回；概览和「出口与地区组」页显示当前由哪个枢纽承载，地区组的实际状态读自那个枢纽。完整规则和这一版**拒绝**的组合（备用枢纽上的 Mesh 等）见[架构](architecture.md)「主枢纽与备用枢纽」。拓扑写法的完整例子是 `internal/defaults/dualhub.go`（`DualHubExample`）。以上都只有自动化测试和没执行过的命名空间测试，**没有在真实主机上走过**。

### 多台国内中继同时分担

有两台及以上国内中继时，它们同时承载主链路，新连接按网关测得的质量自动加权（规则、默认值、对已有连接的影响见[架构](architecture.md)「多中继同时分担」）：

1. 每台中继在「服务器」里各建一台、在拓扑里各画一个中继节点；每台画**一条**家宽网关 → 中继的链路（`udp_wss_failover` 或 `direct_wg`）和**一条**中继 → 主枢纽的隧道（`direct_wg`）。以后再加中继，照这样画、重新下发即可。
2. 拓扑页「网关设置」→「多中继分担与路径质量」：阈值、持续时间、恢复条件和吞吐探测（开关、大小、速率、间隔、每天预算）都有默认值，留空即可；面板写着每次探测和每天最多会用掉多少中继流量（估算）。改了要重新安装到网关。
3. 下发顺序同上：出口 → 枢纽 → 每台中继 → 网关。IX 上每条中继隧道各占一个 WireGuard 端口（端口规划自动给出，预检核对占用）。
4. 网关的测量和决定由宿主机上的 `/usr/local/bin/meridian path-step` 完成（由切换服务每 5 秒调用一次，和面板容器无关），所以**先用新代码跑 `install.sh` 升级宿主机二进制**再安装；旧二进制没有这个子命令时，切换服务按应急规则运行（能通的中继等权重分担、只按通断剔除），面板显示「应急规则在运行」。

示例拓扑在 `internal/defaults/dualhub.go`（`SharedRelaysExample`）。这部分只有自动化测试和命名空间测试，**没有在真实主机上走过**：真实中继的同时承载、真实晚高峰限速下的降权和剔除、吞吐探测的真实流量都没有观察过。

### 预检发现冲突时怎么办

预检只读，发现冲突时**拒绝并说明**，不替你改别的服务。阻断项不能跳过；处理完再点「重新预检」。常见的几类：

| 发现 | 意思 | 怎么处理 |
| --- | --- | --- |
| `not_root` | 登录用户不是 root | 服务器改用 root（这一版不支持 sudo） |
| `os_unsupported`、`arch_unsupported`、`no_systemd` | 不是 Debian 12 / 13、不是 x86_64 / aarch64，或没有 systemd | 换系统；面板不会在别的环境上装 |
| `forward_policy_drop`（警告） | Docker 把 FORWARD 策略设成了 DROP，主机上有 DOCKER-USER，可以共存 | 看「主机防火墙：在 DOCKER-USER 里加的放行规则」那一栏：面板会在 DOCKER-USER 顶部加几条只匹配隧道接口的 ACCEPT（注释 `meridian-fw-…`），不改 Docker 的链和策略；Docker 重启时自动加回，撤回时按注释删除。用 `netfilter-persistent save` 的主机撤回后要再保存一次 |
| `forward_policy_drop`（阻断） | FORWARD 是 DROP，但不能安全共存：没有 DOCKER-USER、ufw 或 firewalld 在运行、FORWARD 在跳到 DOCKER-USER 之前就有 DROP、别的 nft 表（例如 `inet filter`）有 policy drop 的转发链，或这是网关 | 按结论里写的那一条处理：停用 ufw / firewalld，或把隧道接口的转发加进它们自己的放行规则，或换服务器；网关上按第 2 节写好 `daemon.json` 后重启 |
| `nftables_flush_on_reload`（阻断） | nftables.service 已启用或在运行，而它的 reload / restart / stop 会清空整个规则集（`/etc/nftables.conf` 的 `flush ruleset`，或 Debian 单元的 `ExecStop=nft flush ruleset`），连 Meridian 的表一起 | 不需要它：`systemctl disable nftables.service`，然后找时间重启主机（**不要** `systemctl stop nftables`：它会清空所有规则，包括 Docker 的）。需要它：把 `flush ruleset` 改成只删它自己的表（`table inet filter` + `delete table inet filter` 放在定义之前），再 `systemctl edit nftables.service` 写 `[Service]` 和一行空的 `ExecStop=`，`systemctl daemon-reload` 后重新预检 |
| `wan_interface_missing`、`wan_no_default_route` | 节点的 WAN 接口（没填时按 `eth0`）在主机上不存在，或默认路由不在它上面；结论写出默认路由实际所在的网卡（例如 `ens5`、`enp0s6`） | 点「去拓扑修改」，把节点的「WAN 接口」填成那块网卡，保存后重新预检。面板不会自己换名字 |
| `ipv6_ra_unmanaged` | 这个节点要转发 IPv6，而主机的 IPv6 默认路由来自路由通告、由 systemd-networkd 之类的程序处理（`accept_ra=0`）；打开转发后可能断掉 IPv6 | 在拓扑里关掉这个节点的 IPv6 出口，或给网卡配静态 IPv6，或把通告交回内核处理，然后重新预检 |
| `ipv6_ra_kept`（信息） | 主机的 IPv6 来自路由通告（`accept_ra=1`）：装机会在打开 IPv6 转发之前把那块网卡设为 `accept_ra=2`，否则几分钟到几小时后 IPv6 会断 | 不用处理；撤回不会改回去（转发仍开着），重启后回到原样 |
| `cloudflare_warp`、`warp_sidecar_conflict` | 主机上有 WARP 客户端：预检列出它的规则、表 65743 有没有默认路由、谁在用它（进程名、resolv.conf） | 不冲突时只是信息；规则优先级或标记撞上时阻断。这台主机上 Mesh 部署会被拒绝（`host_warp`），直到旧客户端停用（后续版本的单独步骤） |
| `port_in_use` | WireGuard 端口（例如 51820 被已有的 `wg0` 占用）、WSS 的 443（nginx、另一个 wstunnel）、wstunnel 本地端口或解析器的 :53 已被别的进程占用 | 点结论里的「去拓扑修改」，按它说的改链路的「WireGuard 端口」/「wstunnel 本地端口」或节点的「WireGuard 监听端口」/「WSS 监听端口」（WSS 在节点的「WSS 入口（高级）」里），保存后重新预检；对端的 `Endpoint` 随之更新，已装好的对端节点要重新下发、网关要重新安装。解析器的 53/853 不能改：让占用者只绑它自己的地址。端口规则见 [架构](architecture.md)「端口从哪里来」 |
| `interface_exists`、`address_overlap`、`route_overlap`、`route_table_in_use`、`fwmark_in_use`、`nft_table_exists` | 主机上已有同名接口，或重叠的地址 / 路由 / 路由表 / 标记 / `inet meridian` | 改拓扑里的名字或前缀，或移走主机上的旧配置 |
| `path_occupied`：要写的路径上有不属于 Meridian 的文件 | 例如另一份 `/etc/smartdns/smartdns.conf` | 先自己备份并移走；面板不覆盖 |
| `modified_since_install`（警告） | Meridian 装过的文件之后被改过 | 看清改了什么；继续安装会整份覆盖它 |
| `managed_by_other`：主机属于另一个节点或另一个面板 | 部署清单里的节点或部署 ID 不同 | 先在原来那边撤回，或换服务器 |
| `legacy_install` | 旧版本装过、没有清单 | 第 9 节「旧版清理」 |
| `previous_run_incomplete` | 上一次装机没有正常结束 | 第 9 节「恢复中断的装机」 |
| 登录方式不被接受（连接错误 `auth_method_unavailable`） | 服务器不提供这种登录方式 | 按面板给出的公钥加进 `authorized_keys`，改用密钥凭据；只接受密码的服务器用密码凭据即可，面板不强制密钥 |
| 「服务器暂时拒绝面板的来源地址（限速）」（`ssh_rate_limited`） | 服务器（OpenSSH 9.8+ 的 PerSourcePenalties）在 SSH 握手前回了 `Not allowed at this time`：短时间内来自同一地址的连接太多或有没登录完的连接；经端口转发的服务器上所有连接都来自转发器的地址 | 不是密码或指纹问题，什么都不用改。面板 60 秒内不再连接这台服务器，按钮显示倒计时；之后仍被拒就再多等几分钟（连续尝试会延长限速）。少点「重新获取指纹」（只读指纹的连接没有登录，最容易触发限速） |

警告不阻止执行，但执行前复核时出现的**新**警告会让这次执行被拒（`preflight_changed`），要重新审阅。

装好之后远端节点上多了两个单元：`meridian-node.service`（开机在网络、nftables.service 和 Docker 之后执行 `meridian-up.sh`；装完是 enabled、inactive，重启后应是 active）和有 Docker FORWARD DROP 时用的 `meridian-fwcompat.service`（Docker 每次启动后重新加 DOCKER-USER 规则）。`meridian-up.sh` 只改受管接口和拓扑网卡上的 rp_filter / 重定向，不再碰 Docker、WARP 的接口。这些只在自动化测试里跑过，没有在真实服务器上运行过；第一次在真实服务器上装完后，按 [验收清单](verification.md)「与已有业务共存」里的只读命令核对。

同一流程里面板只登录一次：连接测试之后紧接着的预检、一次装机里的预检重跑和脚本、撤回的计划和执行共用一条已认证的连接（空闲 60 秒或存在 5 分钟就关闭；改服务器、指纹或凭据会立即关闭）。这一点和限速识别一样，只在自动化测试里验证过，没有在真实服务器上运行过。完整的检查列表和它不检查的东西见 [架构](architecture.md)「装机前预检」。

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
  4. 确认计划里每个节点都关联了可操作的服务器（Cloudflare 页的部署卡片会列出缺服务器、缺凭据或缺已确认指纹的节点，有任何一个就拒绝部署；连接测试建议先做，但不是这里的关卡），点「部署 Mesh」。面板依次：计划校验 → 远端预检 → 为每台主机创建 Cloudflare Mesh 节点 → 写入 compose / `meridian-mesh-up.sh` / `mesh.env`（0600）并启动 sidecar → 健康检查 → 发布路由 → 枢纽重新封装。任何一步失败都会撤回本次创建的东西；补偿没做完时面板会列出来，修好后点「撤回 / 重试补偿」。部署记录固定了每台主机的服务器 ID、凭据 ID、地址、端口、用户和已确认的主机指纹，以及 Cloudflare 账户：撤回只连接这些主机并要求同一指纹（之后在拓扑里删节点不影响撤回；被固定的服务器和凭据在撤回完成前不能删除或改指向，凭据可以原地轮换），只用原账户的凭据；撤回完成前面板拒绝切换到别的账户，同一账户可以更换 token。
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

## 9. 撤回（卸载）与失败后的恢复

**从拓扑删除节点不会动服务器。** 删除时面板会问：「仅从拓扑删除（保留服务器上的安装，之后仍可在部署页撤回）」还是「先撤回再删除」。只删拓扑时，部署记录照旧保留绑定的服务器、地址、端口、用户、主机指纹和凭据，部署页继续显示「节点已从拓扑删除，安装仍在服务器上」；在撤回完成之前，这台服务器和这份凭据不能删除或改指向（凭据可以原地轮换），节点也不能装到另一台服务器上。

**撤回远端节点**（部署页 → 部署记录 → 撤回）：

1. 「生成撤回计划」：面板经已固定指纹的 SSH 在**部署时的那台主机**上只读运行固定的撤回脚本，列出服务器上清单记录的服务、接口、路由表、nft 表和文件，以及要保留的东西。清单属于别的节点、别的面板部署或别的服务器时直接拒绝并说明原因；服务器的地址或指纹和部署时不同也拒绝。
2. 输入节点 ID 确认后执行。计划生成之后服务器上的状态变了会被拒绝（重新生成计划即可）。
3. 结果分三列：已移除 / 保留（有意）/ 没能移除。装机后被你改过的文件不会被删除，会列在「没能移除」里；处理后再撤回一次（可以重复执行，已经不在的东西跳过）。
4. 有意保留：装上的软件包（wireguard-tools、nftables，以前的版本装的 smartdns）、运行中的转发（Docker 也依赖它）、`all.send_redirects` 和拓扑网卡的 rp_filter / 重定向值（到重启前不变；`99-meridian.conf` 已删，重启后不再设置）、清单之外的一切（Docker 和它的链与策略、WARP、别的 WireGuard 接口和 nft 表、DOCKER-USER 里你自己的规则）。DOCKER-USER 里带 `meridian-fw-` 注释的规则会被删除（先停用 `meridian-fwcompat.service`，Docker 之后重启也不会加回来）。

节点上还部署着 Mesh 时先在 Mesh 部署卡片撤回 Mesh（它按部署时的主机和 Cloudflare 账户撤回），再撤回节点。服务器已经不存在（VPS 已删除）时可以「放弃」：记录标为已放弃并解除绑定，面板明确说明它**没有核实**服务器上是否还有东西。

**恢复中断的装机**和**旧版清理**走同一个对话框（计划 → 确认 → 结果），入口在预检结果的对应阻断项旁边，也在部署记录里。

**撤回网关**（部署页 → 网关 → 撤回网关，输入 `gw` 确认）：面板经 `meridian-host` 的固定动作，在一份持久事务里先关掉转发、停掉 `meridian.service`，再按安装清单删除 WireGuard 接口、服务、路由表和规则、`inet meridian` 表和清单里的文件。**局域网兜底表 `inet meridian_guard` 和它的开机文件保留**：仍把网关当默认网关的设备会断网，而不是经 ROS 直出；重启后 `meridian-guard.service` 照样加载它。任一步失败都会补偿回撤回前的运行状态；补偿也失败时页面显示未完成的事务，修好后点「恢复」。之后：

- 重新使用 Meridian：再做一次安装前预检并「安装到网关」（不能用回滚恢复）。
- 彻底不用：点「移除兜底表」（单独确认）。此后局域网不再由 Meridian 兜底，转发保持关闭，直到别的东西打开它。宿主上的 `meridian.service`、`meridian-guard.service`、`meridian-host.service` 和面板容器属于 install.sh 的安装，撤回不动它们；要连这些一起去掉，按第 2 节反过来手工 `systemctl disable --now` 并删除单元文件。

以上流程只在仓库的自动化测试里跑过（本机沙箱、进程内 SSH 服务器、模拟宿主），**还没有在真实服务器或网关上执行过**；第一次在真实主机上使用前，按 [验收清单](verification.md)「撤回与恢复」在可以随意重装的机器上走一遍。

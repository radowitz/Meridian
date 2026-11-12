# 在 Debian 13 上安装

目标机器是一台新的 Debian 13，和 ROS `192.168.100.1` 在同一个二层，地址 `192.168.100.88/24`。不要改 ROS，不要停旧的 mihomo，也不要把这台机器的上游接到旧网关后面。

## 1. 地址和转发

局域网口静态地址示例（接口名按实际修改，下面用 `eth0`）：

```text
address 192.168.100.88/24
gateway 192.168.100.1
```

默认路由经 ROS，这样机器自己的更新和 WireGuard 外层握手走国内出口。策略路由只处理从测试设备转发进来的流量。

确认没有在这台机器上启用 radvd 或 DHCP。地址 `192.168.100.1` 必须仍然是 ROS。

## 2. 主机准备

```bash
sudo bash deploy/debian/install.sh
```

脚本会：

- 写入 `/etc/sysctl.d/99-meridian.conf`（转发、`rp_filter=2`、关闭发送重定向、局域网口 `accept_ra=2`）
- 若存在 systemd-resolved，关掉它的 53 端口占用，把 53 留给 SmartDNS
- 用发行版软件包安装 `docker.io`、`docker-compose-v2`（没有这个包时才用 `docker-compose`）、`wireguard-tools`、`nftables`、`openssl`
- 把 Docker 的 `iptables` / `ip6tables` 设为 false（仅当还没有 `/etc/docker/daemon.json`）。否则 Docker 会把 FORWARD 改成 DROP，测试设备的流量被丢掉
- 启用 `meridian.service`，开机时若 `/usr/local/sbin/meridian-up.sh` 已存在就只恢复 Meridian 自己的表和路由
- 不停止、不修改任何名字里带 mihomo 的服务

脚本不会自动改网卡地址。如果当前没有 `192.168.100.88`，它只打印警告。

## 3. 启动面板

```bash
sudo docker compose -f deploy/docker-compose.yml up -d --build
```

容器使用 host 网络、`NET_ADMIN` 和 `/dev/net/tun`，这样它能操作宿主机的 WireGuard 和 nftables。面板默认只绑 `192.168.100.88:8787`。进程拒绝监听 `0.0.0.0`，避免把面板暴露到非局域网地址。

首次启动会在 `/var/lib/meridian/panel.token` 写入口令（权限 0600），日志里只有文件路径。浏览器打开 `http://192.168.100.88:8787`，把这串口令填进面板。也可以事先设置 `MERIDIAN_TOKEN`。

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

1. **校验路径**。缺 IX、Mesh 绕过、NAT 方向错误、Netflix 没走家宽，都会报错并拒绝保存。
2. **演练**。只产生差分，不写文件。
3. **写入数据目录**，确认后再 **安装到本机**。安装只会覆盖 Meridian 自己的 WireGuard、nftables、sysctl、SmartDNS 和脚本，并且先 `nft delete table inet meridian`。

远程节点用面板里的「生成脚本」演练。确认无误后，用你自己的 SSH 密钥调用 `POST /api/provision`（`dry_run=false`）。演练响应里不会出现新生成的私钥明文。

wstunnel 需要单独安装到 `/usr/local/bin/wstunnel`，版本请钉死你核对过的 [erebe/wstunnel](https://github.com/erebe/wstunnel/releases) release。脚本不会从网络上直接下载二进制。

## 5. 名单

在网关上，配置安装好并且 nftables 表已经存在之后：

```bash
sudo /usr/local/sbin/meridian-update-chnroute.sh
sudo /usr/local/sbin/meridian-update-geosite.sh
sudo systemctl restart smartdns
```

SmartDNS 可以装在宿主机上，也可以在配置文件就位之后用 Compose 的 `dns` profile 拉起：

```bash
sudo docker compose -f deploy/docker-compose.yml --profile dns up -d
```

上线前把 `pymumu/smartdns:latest` 钉成你核对过的摘要。然后按 [测试设备](test-device.md) 把一台电脑指过来，用 [验收清单](verification.md) 检查泄漏。

## 6. 和 ROS 同网段时

- `rp_filter` 必须是 loose（2）。国内回程可能由 ROS 直接交给客户端。
- 关闭本机发送 ICMP 重定向。ROS 自己仍可能对客户端发重定向，这不在这台机器的控制范围内。
- 不要做代理 ARP，不要占用 `.1`。

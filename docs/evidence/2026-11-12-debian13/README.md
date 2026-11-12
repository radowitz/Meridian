# 执行记录：2026-11-12，Debian 13 测试网关

这里存的是[验收清单](../../verification.md)里「隔离 Linux 集成证据」一类的原始输出。它们说明这些脚本和测试在一台真实的 Linux 主机上按文档跑过并通过，**不是**泄漏签收：真实测试机上的 DNS / WebRTC、ROS 的 `fd00::/8` 查询、断隧道和抓包仍然是「待人工签收」。

## 环境

- 一台全新的 Debian 13（trixie）x86_64 虚拟机，内核 6.12.116，nftables 1.1.3，systemd 257，Docker 26.1.5 + Compose 2.26.1，SmartDNS 镜像 `pymumu/smartdns:latest`（smartdns 1.2026.11.09），wstunnel 11.1.0。
- 局域网口由 DHCP 取得 `192.168.100.88`（ifupdown `allow-hotplug`），网卡名不是 `eth0`。
- 用 `MERIDIAN_IMAGE_TAR` 离线镜像包走 `deploy/debian/install.sh` 的首次安装，再从面板「安装到本机」。
- 拓扑是仓库示例：对端端点是文档地址，对端公钥是临时生成的，**隧道没有握手**。所以这里没有任何经过真实出口的流量，也没有真实客户端。
- 日志里的本地证据目录路径和 ROS 的链路本地地址已隐去，其余原样。

## 文件

| 文件 | 命令 | 结果 |
| --- | --- | --- |
| `netns-reload.log` | `sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsReloadNoLeak$' -test.v`（开发机上 `GOOS=linux go test -c ./internal/compile` 交叉编译后拷过去） | PASS。对照阶段境外 IPv6 确实漏到 ROS；首次安装、200 次重载、两种加载失败注入、只剩兜底表四个阶段境外 v4/v6 到 ROS 都是 0 |
| `mesh-veth.log` | `sudo bash deploy/verify-mesh-veth.sh` | 8 项 PASS。v4/v6 经显式下一跳转发；对照的 `default dev mmesh` 在两个地址族都不转发 |
| `verify-host-exec.log` | `sudo bash deploy/verify-host-exec.sh` | 18 项 ok |
| `verify-host-exec-boot.log` | 重启后 `sudo bash deploy/verify-host-exec.sh --boot` | 24 项 ok。兜底表先于 systemd-sysctl 和 dockerd 加载；`meridian.service` 等到局域网地址后自行完成 |
| `verify-smartdns.log` | `sudo bash deploy/verify-smartdns.sh`（`geosite/cn.txt` 里手工放了两个测试域名） | `meridian-smartdns-verify-ok` |
| `meridian-verify.log` | `sudo /usr/local/sbin/meridian-verify.sh` | 17 PASS、5 PENDING-HUMAN、4 NOT-RUN-HERE，结尾 `meridian-verify-local-ok` |

## 同一次测试里手工核对过、没有单独日志的

- 首次安装后（未重启）：`ip_forward` 和 `all.forwarding` 都是 0，`iptables -S FORWARD` 是 ACCEPT，没有 Docker 留下的 nft 表，`/etc/wireguard` 是 0700。
- 「安装到本机」：WireGuard 配置 0600、没有占位符；私钥只在这三个配置和面板数据库里，API 响应、编译产物、面板和 `meridian-host` 日志、快照、已安装副本里都搜不到。
- 激活失败（缺 wstunnel）：返回失败并补偿到事务前，没有残留接口、表和单元。
- 删掉一条网关链路再安装：对应接口、`.conf`、wstunnel 单元消失；手写的 `m99.conf` 和 `m99` 接口不动。
- 运行态回滚：`{}` 被 409 拒绝；`install=true` 把新加的接口、文件、单元清掉。
- 在转发中的网关上重跑 `install.sh`（升级模式）：每 0.2 秒采样一次，两个转发开关全程是 1，`meridian-restore-ok`。
- 对端没有公钥、网关节点 `lan_interface` 与设置不一致：分别 422 拒绝，宿主上没有写入。
- 名单脚本：默认源不可达时在限定时间内退出，已有集合不变；用 `MERIDIAN_*_BASE_URL` 换源后 chnroute 两个集合写入。
- 面板发起解锁探测（隧道不通）：全部「探测失败 · 出口未确认」，没有平台结论；带出口标记或中转源地址从局域网口发出的包是 0。
- systemd 257 上 `RestartForceExitStatus=75`：oneshot 单元退出 75 会被重试，退出 1 不会。

## 这次测试发现、已在同一批改动里修掉的

SmartDNS 容器命令缺可执行文件；生成的 `bind-tls` 证书写法和重复绑定让 SmartDNS 起不来；`install.sh` 先装 Docker 后写 `daemon.json`，留下打开的转发和 `FORWARD DROP`；DHCP 地址晚到时 `meridian.service` 开机失败；两个 `lan_interface` 可以不一致；对端缺公钥要到 `wg setconf` 才报错；名单脚本没有超时；`verify-mesh-veth.sh` 的 IPv4 邻居检查把 IPv6 表项算了进去。

## 仍然没有验证的

- 任何经过真实隧道和真实出口的流量；真实客户端的 DNS / WebRTC；ROS；断隧道；抓包。
- Cloudflare Mesh：没有调用过真实 API，没有跑过真实 sidecar 镜像。
- 解锁探测的平台判定：没有对真实平台发过请求。
- 远端节点的 provision 脚本。

# 测试设备

只改用来验收的那一台。其他设备继续用 ROS 的 DHCP 和现有 mihomo，不要动。

回滚就是把这台设备的网关和 DNS 改回原来的值，一般是 `192.168.100.1`。不要在 `192.168.100.0/24` 上再开一个 DHCP。

## IPv4

- 地址：保持 ROS 已经分配的地址，或在 `192.168.100.0/24` 里挑一个没人用的
- 掩码：`255.255.255.0`
- 网关：`192.168.100.88`
- DNS：`192.168.100.88`

只保留这一条默认路由。

## IPv6

ROS 只通告 GUA，不通告 DNS，RA 生存期 2700 秒，会反复把默认路由写回 ROS。测试机必须关掉路由器发现，再手工加上指向 Meridian 链路本地地址的默认路由。否则 AAAA 和 WebRTC 会从家庭运营商前缀出去。

只有这样配好 IPv6 的设备，才配得上网关设置「客户端 IPv6 经本网关」（`clients_ipv6_via_gateway`）打开；局域网里还有一台没这样配的设备，就保持关闭（默认）。

### 手机（不动 IPv6）

iOS 和 Android 的 Wi-Fi 设置里只能手填 IPv4 地址、网关和 DNS，IPv6 地址和默认路由总是来自 ROS 的 RA，没有办法指向网关。对这类设备：

- 只改 IPv4：网关 `192.168.100.88`，DNS `192.168.100.88`。IPv6 不用管，也管不了。
- 「客户端 IPv6 经本网关」保持关闭（默认）。这时网关解析器对国内名单以外的域名一律不返回 AAAA（空回答），手机拿不到国外网站的 IPv6 地址，只能用 IPv4 连，IPv4 经网关进隧道：被封的网站不再先卡在 IPv6 上，没被封的国外网站也不会从家宽 IPv6 静默直连。
- 国内名单里的域名照常有 AAAA，手机经 ROS 用 IPv6 直连，这本来就是直连。
- 仍然管不到的：手机自己用 IPv6 地址直连的流量（不经 DNS 的 App、写死的地址）、WebRTC 的 IPv6 host 候选，以及手机自己的加密 DNS：iOS 装了加密 DNS 描述文件、或 Android「私人 DNS」填了主机名时，查询不经网关解析器（网关劫持的 853 证书对不上，严格模式直接失败）。Android 设成「自动」或「关闭」，iOS 不装这类描述文件。
- 验证（实机人工签收）：手机上打开 ipleak.net，IPv6 一栏不应出现家宽的 GUA 访问国外网站的记录；网关上 `dig @192.168.100.88 AAAA www.google.com` 是 NOERROR、没有回答。2026-11-13 主会话在用户的真实网关上看到过网关这一侧的行为（走隧道的名字没有 AAAA、名单内的国内名字有 AAAA、`meridian-verify.sh` 的 `dns_aaaa_tunnelled` 通过），只是一次观测，没有存档的日志；**手机上的这项签收还没有做过**。

打开「未列名单的域名也问国内 DNS」时手机这边不用改；泄漏测试网站会多出国内解析器，见[验收清单](verification.md)「DNS」。

先在网关上查局域网口的链路本地地址：

```bash
ip -6 addr show dev eth0 scope link
```

下面用 `fe80::88` 代替，接口名按测试机实际修改。

### Linux

```bash
sudo sysctl -w net.ipv6.conf.eth0.accept_ra_defrtr=0
sudo ip -6 route replace default via fe80::88 dev eth0
```

想开机仍生效，把 `accept_ra_defrtr=0` 写进 sysctl，并在网络配置里保留这条默认路由。已经通过 SLAAC 拿到的 GUA 可以留着，国内 IPv6 还要用它。

### Windows

在管理员 PowerShell 里，把 `Ethernet` 换成网卡名：

```powershell
netsh interface ipv6 set interface "Ethernet" routerdiscovery=disabled
netsh interface ipv6 add route ::/0 "Ethernet" fe80::88
```

DNS 填 IPv4 的 `192.168.100.88` 即可。ROS 的 RA 里没有 DNS，不会和这项冲突。

## iOS 联网检测复测（「无线局域网没有接入互联网」）

用户报告 iPhone 连上这台网关（手填 IPv4 网关和 DNS）后提示 Wi-Fi 没有接入互联网。**这个问题不知道是否已经解决**：AAAA 和未列名单解析的修复上线后，还没有取得任何设备上的证据，原因也没有定位。苹果的联网检测名字（`captive.apple.com` 等）在 `apple` 名单里，网关按设计用国内解析器解析、直连；这只是配置推断，不是观测。复测时按下面做，结果记进「签收记录」，不能写成「已修复」，除非下面的检查在设备上真的成功、并有记录。

复测步骤：

1. 手机：只改 IPv4（网关、DNS 都填网关地址），不装加密 DNS 描述文件，关掉「私有无线局域网地址」的轮换（让地址在复测期间不变），记下手机的 IPv4 地址，下面写作 `C`。
2. 网关：先开抓包（下面的配方），再在手机上「忽略此网络」后重新加入，或者开关一次飞行模式；等提示出现或不出现，最多 2 分钟；然后在 Safari 里打开 `http://captive.apple.com/hotspot-detect.html`，应该看到 `Success`。
3. 记下：是否出现提示、出现的时间、Safari 是否显示 `Success`、当时面板的拓扑版本、两个 DNS 设置的值、默认地区组当时的成员。

抓包配方（只在网关的局域网口、只针对这一台手机、只要头部；用 root 运行，文件不要放进仓库）：

```bash
C=192.168.100.50            # 手机的 IPv4，换成实际值
IF=eth0                     # 网关的局域网口
D=/root/ios-capture-$(date +%Y%m%d-%H%M); mkdir -p "$D"; chmod 700 "$D"
# 1. 手机发给网关解析器的 DNS 查询和回答（名字和地址要看，所以截到 512 字节）
tcpdump -i "$IF" -nn -s 512 -w "$D/dns.pcap" "host $C and port 53" &
# 2. TCP 的建立与失败：只有 SYN / RST / FIN 的包，96 字节只含 IP+TCP 头
tcpdump -i "$IF" -nn -s 96 -w "$D/tcp-ctl.pcap" "host $C and tcp and (tcp[tcpflags] & (tcp-syn|tcp-rst|tcp-fin) != 0)" &
# 3. 苹果的联网检测：明文 HTTP 80，截到 256 字节（请求行、状态行附近，不要正文）
tcpdump -i "$IF" -nn -s 256 -w "$D/http80.pcap" "host $C and tcp port 80" &
# 4. 同一时间的连接跟踪：只有 SYN 发出、没有回应的连接
( for i in $(seq 1 24); do date +%T; conntrack -L -s "$C" -p tcp --state SYN_SENT 2>/dev/null; sleep 5; done ) > "$D/conntrack-synsent.txt"
kill %1 %2 %3
```

看什么：

- `dns.pcap`：`captive.apple.com`（以及 `www.apple.com`、`*.apple.com` 的检测名字）有没有查询、回答的 rcode、A 记录是什么、用了多久；有没有查询得到 SERVFAIL 或没有回答。
- `tcp-ctl.pcap`：发往检测名字解析结果的 SYN 有没有 SYN-ACK；只有 SYN（重传）没有回应、或者收到 RST 的目标地址列出来。`conntrack-synsent.txt` 里长时间停在 SYN_SENT 的连接对照着看。
- `http80.pcap`：`GET /hotspot-detect.html` 有没有发出、有没有 `HTTP/1.1 200`，以及回答是不是来自苹果的地址。
- 手机的 IPv6 不经过这台网关（来自家里路由器），它的 IPv6 检测流量在网关上看不到；需要时在 ROS 上对同一台手机另外抓（`/tool sniffer`，同样只要头部）。

脱敏（之后只把脱敏的文字摘要放进签收记录或证据目录，pcap 原件留在网关上或删除；网关上没有 `tshark` 时把 pcap 拷到自己的电脑上转换，转换后删掉副本）：

```bash
tshark -r "$D/dns.pcap" -T fields -e frame.time_relative -e ip.src -e ip.dst \
  -e dns.qry.name -e dns.qry.type -e dns.flags.rcode -e dns.a -e dns.aaaa > "$D/dns.txt"
tshark -r "$D/tcp-ctl.pcap" -T fields -e frame.time_relative -e ip.src -e ip.dst \
  -e tcp.dstport -e tcp.flags.str > "$D/tcp-ctl.txt"
```

- 只保留复测那两分钟内的行。
- 把手机地址换成 `CLIENT`，网关地址换成 `GATEWAY`；家里的公网 IPv4、IPv6 前缀、MAC 地址一律不出现（上面的字段里没有 MAC）。
- 苹果检测名字和苹果的地址可以保留；**其他所有域名换成 `name-1`、`name-2`…，其他所有公网地址换成文档地址段**（`192.0.2.x`、`198.51.100.x`、`203.0.113.x`、`2001:db8::/32`），对应关系不留在记录里。
- 不放 HTTP 正文、Cookie 或任何请求头（`-s 256` 只截到请求行附近；摘要里只写请求行和状态行）。

## 签收记录

这台设备上做的 DNS 泄漏、WebRTC、断隧道和抓包是[验收清单](verification.md)里的「实机人工签收」，仓库测试、面板和 `meridian-verify.sh` 都替代不了。每做一项，记下日期、当时的拓扑版本（面板快照）、这台设备的 IPv4/IPv6 默认路由（`ip route`、`ip -6 route` 或 `route print` 的输出），以及截图或 pcap 的存档位置。没有记录的项目按「待人工签收」处理。

远程接入的手机不是这台测试设备：它的验收步骤（蜂窝网络、两种模式、路由器转发）见 [远程接入](remote-access.md)「验证」，签收记录的要求相同。dnsleaktest / ipleak 上看到的出口地区要和当时默认地区组（或规则指向的组）实际选中的出口一致；记录时把面板「出口」页上该组的当前成员也写下来。

## 不要做的事

- 不要只改 IPv4 网关、不改 IPv6 默认路由。
- 不要让测试机同时留下 ROS 的 IPv6 默认路由。
- 不要把 Meridian 当成全屋 DHCP 或 RA 服务器。

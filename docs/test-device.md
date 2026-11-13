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
- 验证（实机人工签收）：手机上打开 ipleak.net，IPv6 一栏不应出现家宽的 GUA 访问国外网站的记录；网关上 `dig @192.168.100.88 AAAA www.google.com` 是 NOERROR、没有回答。这台网关上的这一组行为**还没有在真实网关上验证过**。

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

## 签收记录

这台设备上做的 DNS 泄漏、WebRTC、断隧道和抓包是[验收清单](verification.md)里的「实机人工签收」，仓库测试、面板和 `meridian-verify.sh` 都替代不了。每做一项，记下日期、当时的拓扑版本（面板快照）、这台设备的 IPv4/IPv6 默认路由（`ip route`、`ip -6 route` 或 `route print` 的输出），以及截图或 pcap 的存档位置。没有记录的项目按「待人工签收」处理。

远程接入的手机不是这台测试设备：它的验收步骤（蜂窝网络、两种模式、路由器转发）见 [远程接入](remote-access.md)「验证」，签收记录的要求相同。dnsleaktest / ipleak 上看到的出口地区要和当时默认地区组（或规则指向的组）实际选中的出口一致；记录时把面板「出口」页上该组的当前成员也写下来。

## 不要做的事

- 不要只改 IPv4 网关、不改 IPv6 默认路由。
- 不要让测试机同时留下 ROS 的 IPv6 默认路由。
- 不要把 Meridian 当成全屋 DHCP 或 RA 服务器。

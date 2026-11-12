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

## 不要做的事

- 不要只改 IPv4 网关、不改 IPv6 默认路由。
- 不要让测试机同时留下 ROS 的 IPv6 默认路由。
- 不要把 Meridian 当成全屋 DHCP 或 RA 服务器。

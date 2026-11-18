# 执行记录：2026-11-16，局域网到隧道端点（命名空间）

> **åå²è®°å½ï¼å¼æºåè±æï¼2026-11-18ï¼ã** æ¬ç®å½æ¥å¿éçå±åç½å°åãç½å¡åãç«¯å£ãèç¹ ID åèç¹åå·²æ `docs/privacy-inventory.md` çç»ä¸æ å°æ¢æææ¡£å°åæ®µï¼192.0.2.0/24 ç­ï¼ååæåç§°ï¼æ²¡æéè·ï¼ç»æè¡æªæ¹ãæ¥å¿å¯¹åºçæ¯å½æ¶çä»£ç çæ¬ï¼ä¸ä»£è¡¨å½åçæ¬çéªè¯ã

属于[验收清单](../../verification.md)里「隔离 Linux 集成证据」一类：`TestNetnsEndpointAccess` 在开发机的特权 Linux 容器里跑过并通过。**不是**真实网关、真实 WireGuard / wstunnel 或真实出口的证据，也不是目标发行版内核上的证据。

## 代码版本和环境

- 代码：`/private/tmp/meridian-review` 的工作区（未提交的改动之上，包括 `internal/validate/endpoint_access.go` 和 `render_nft.go` 的端点集合）。
- 主机：Mac 上的 Docker Desktop，本地镜像 `meridian-p2-lab:latest`（arm64，Debian 13 用户态，nftables 1.1.3，iproute2、python3），内核 6.10.14-linuxkit。`--privileged --network none`：不联网，只在容器里的临时网络命名空间里进行。
- 测试二进制：`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o compile.test ./internal/compile`（SHA-256 `007faba9…8c537a`）。

## 命令

```
docker run --rm --privileged --network none -v $PWD/compile.test:/compile.test:ro \
  -e MERIDIAN_NETNS_TEST=1 --entrypoint /compile.test meridian-p2-lab:latest \
  -test.run '^TestNetnsEndpointAccess$' -test.v
```

## 文件

| 文件 | 结果 |
| --- | --- |
| `netns-endpoint-access.log` | PASS，59 秒，第一次运行即通过。主链路：中继 `203.0.113.10`、IX 国内入口 `198.51.100.10`、中继 IPv6 `2001:db8:a1::10` 经本地宽带（服务端看到客户端自己的局域网地址，经局域网口和 ROS，隧道 0）；dc2 `203.0.113.42`、备用枢纽 `203.0.113.30` 服务端看到 dc1 的 WAN `100.64.1.2`，dc1 `203.0.113.41`、IX 出口 `203.0.113.20` 由节点本身应答，都经默认组隧道，局域网口 0、ROS 0；`2001:db8:42::42`（默认组不承载 IPv6）丢弃。备用枢纽承载时：客户端到 `203.0.113.30` 经 `m02`，网关带 `0x4d72` 的 10 个 ICMP 和一条到 `:8443` 的 TCP 都从局域网口经主表出去、进隧道 0；客户端 10 个 ICMP 在备用隧道上恰好 10 个包。无默认出口目标时（渲染器的兜底，校验本来拒绝这种拓扑）所有境外端点进 `endpoint_block4`，五个地址全部超时，局域网口 0、ROS 0，中继仍然直连。 |
| `netns-endpoint-access-mutant.log` | **变异检查**：把 `endpoint_tunnel4` 规则的标记临时改成国内标记（`0x64`）重新编译，测试在主链路阶段失败（4 项：服务端看到 `192.0.2.50`，局域网口和 ROS 计数 4、隧道 0）。改动已还原，未保留。 |

## 这份记录没有覆盖的

- 默认组经隧道承载 IPv6 的情况（主备枢纽示例只有 IPv4；只测了 IPv6 国内直连和 IPv6 丢弃）。
- 真实 WireGuard 和 wstunnel：隧道是 veth；网关的外层包用带同样 fwmark 的 ICMP 和不带标记的 TCP 代替。
- 真实内核（Debian 13 主机）上没有执行。

# 执行记录：2026-11-13，Debian 13，地区组解析经 Mesh 备路

[同一天较早的那份记录](../2026-11-13-debian13/README.md)之后，代码改了枢纽和出口的 Mesh 脚本、出口的 nft 和路由，所以那份记录不覆盖这些改动。这里是改动之后重跑的三个命名空间测试的原始输出，属于[验收清单](../../verification.md)里「隔离 Linux 集成证据」一类。**不是**真实 Cloudflare Mesh 的证据，也不是泄漏签收。

## 代码版本和环境

- 代码：第一次包含本目录的那次提交（在 `233e17b` 之上：地区组的解析经 Mesh 备路、Mesh 封装脚本的条件修正、枢纽状态绑定服务器身份、装机前预检）。三个测试只依赖 `internal/compile`。
- 主机：同一台 Debian 13（trixie）x86_64 虚拟机，内核 6.12.116，nftables 1.1.3。测试只在临时的网络命名空间里进行，没有改动这台主机正在运行的数据面。
- 日志里的证据目录路径已隐去，其余原样。

## 文件

| 文件 | 命令 | 结果 |
| --- | --- | --- |
| `netns-group-dns.log` | `sudo MERIDIAN_NETNS_TEST=1 ./compile.test -test.run '^TestNetnsGroupDNSFailover$' -test.v` | PASS，68 秒。第 1–6 阶段与上一份记录相同。第 7–9 阶段：枢纽和出口各自运行**编译出的** `meridian-mesh-up.sh`，对着充当 sidecar 的命名空间完成封装（表 170、只许经 Mesh 接口转发的规则、主机一侧的固定邻居）；Mesh 是两个 tun 设备之间的转发。封装后枢纽把组 `us` 指向 `mmesh`，UDP、TCP 查询由出口 `us` 经 Mesh 应答，局域网客户端的连接经 Mesh 出去；出口一侧到隧道口、公网口和枢纽 sidecar 容器网桥的计数都是 0。Mesh 中断：查询和连接超时。sidecar 未封装：枢纽的组表是黑洞，出口的表 171 没有下一跳，查询超时。每个阶段里未带标记的组查询（除对照阶段故意发的那一个）、从局域网口发出的、到国内解析器和 ROS 的都是 0 |
| `netns-reload.log` | 同一个二进制，`-test.run '^TestNetnsReloadNoLeak$'` | PASS，130 秒 |
| `netns-ula-lan.log` | 同一个二进制，`-test.run '^TestNetnsULALANHomeAccess$'` | PASS，18 秒 |

## 这次测试发现并修掉的

- **编译出的 Mesh 封装脚本把成功和失败判反了。** `meridian-mesh-up.sh` 在 sidecar 里的封装块执行成功时走了失败分支（撤销封装），执行失败时却去探测下一跳并写下「已封装」的标记。原始版本就是这样；此前没有任何测试运行过编译出的这个脚本（`deploy/verify-mesh-veth.sh` 是按同样的命令手工搭的）。第一次运行第 7 阶段时就表现为「hub sidecar not sealed」。条件已改正，并加了直接运行编译脚本的回归测试 `TestMeshUpSealFollowsSidecarBlock`。
- 测试自身：tun 设备要在移入目标命名空间之后再配置和启用；对照阶段故意发的一个未带标记的查询不应计入之后的阶段。

## 这份记录没有覆盖的

- 真实的 Cloudflare Mesh：连接器是否对进入 Mesh 的流量做源地址转换（查询的回程依赖它）、真实 sidecar 镜像里的接口名和路由、真实的延迟和丢包。测试里的源地址转换是假设。
- 真实出口上的解析器、真实枢纽、带客户端的真实故障切换。
- `meridian-verify.sh`、`verify-host-exec.sh`、`verify-smartdns.sh`、`verify-mesh-veth.sh` 没有在这一版上重跑；这一版也还没有安装到任何主机上。

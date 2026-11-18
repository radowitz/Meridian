# 排错

先确定问题在哪一段：**面板/安装** → **预检** → **远端装机** → **隧道** → **分流与 DNS**。下面按这个顺序给出看哪里、怎么判断。

## 面板打不开

- `sudo docker compose -f deploy/docker-compose.yml ps`：容器在不在运行。
- `sudo docker compose -f deploy/docker-compose.yml logs meridian`：
  - `meridian-bind-waiting` / `meridian-bind-not-ready`：监听地址还没出现在网卡上（DHCP 租约没到，或 `MERIDIAN_BIND` 写错）。核对 `deploy/.env` 的 `MERIDIAN_BIND`，必要时 `sudo bash deploy/debian/install.sh --lan-addr <地址>` 重跑。
  - 面板拒绝监听 `0.0.0.0` / `::`，这是有意的。
- 浏览器访问不了但本机 `curl http://<地址>:8787/api/health` 正常：看管理防火墙 `sudo nft list table inet meridian_mgmt`，你的来源是否在局域网接口或 `--allow` 列表里（[install.md](install.md#管理防火墙)）。
- 全新安装提示 `setup_required`：还没用初始化码创建管理员（[快速上手](quickstart.md#2-取一次性初始化码约-1-分钟)）。初始化码过期或输错 5 次后重新运行 `meridian setup-code`。

## 预检报告

预检（远端经已确认指纹的 SSH，网关经宿主代理的 `/v1/preflight`）只读，有阻断项就拒绝执行并说明原因，不替你改别的服务。阻断项不能跳过：处理完点「重新预检」。执行前会再复核一次，出现新的警告时这次执行被拒（`preflight_changed`），重新审阅即可。

最常见的几类：

| 发现 | 处理 |
|---|---|
| `os_unsupported` / `arch_unsupported` / `no_systemd` / `not_root` | 换成支持的系统（Debian 12 / 13 x86_64、Ubuntu 20.04 aarch64），用 root 登录 |
| `port_in_use` | WireGuard / WSS / wstunnel 本地端口被占：按结论里的「去拓扑修改」换端口；端口在 NAT 后面时同时更新转发范围（[FAQ](faq.md#nat-后面的中继要怎么转发端口)） |
| `wan_interface_missing` / `wan_no_default_route` | 节点的 WAN 接口填错，结论里写了默认路由实际所在的网卡 |
| `forward_policy_drop` | Docker 把 FORWARD 设成了 DROP。可共存时只是警告；不能共存（ufw、firewalld、别的 nft drop 链）时阻断 |
| `nftables_flush_on_reload` | `nftables.service` 的重载会清空所有规则，包括 Meridian 的：`systemctl disable nftables.service` 后择时重启，**不要** `stop` |
| `path_occupied` / `managed_by_other` / `legacy_install` / `previous_run_incomplete` | 有不属于这次部署的文件或旧安装：先备份移走、在原处撤回、做旧版清理或恢复中断的装机 |
| `ssh_rate_limited` | 服务器在握手前限速了面板的来源地址，不是密码问题。等倒计时结束再试，少点「重新获取指纹」（[FAQ](faq.md#ssh-被限速--只能经中继管理)） |

完整的发现列表和每一项的处理见[参考手册](../install-debian13.md#预检发现冲突时怎么办)。

## 链路日志

「链路日志」页记录网关看到的**状态变化**：主链路走哪条腿或哪台中继、切到备用枢纽和切回、中继被降权/剔除/恢复、每条隧道握手超时与恢复、WSS 承载的连接与断开、出口自检不通与恢复，以及采集空窗。它不含任何流量内容，随网关安装，没有开关；安装之前发生的不会补记。

怎么读：

- **握手超时**要超过 180 秒没有新握手才记，所以最多晚 3 分钟多才出现，且只代表网关这一端。
- 一条链路只有 **WSS 腿**有握手、**UDP 腿**从来没有：多半是 UDP 被封，或 NAT 转发范围没覆盖这条链路的 UDP 端口（[FAQ](faq.md#nat-后面的中继要怎么转发端口)）。
- 「变化了 N 次」是反复抖动的合并记录，**不是**一次连续中断。
- 「采集空窗」那段时间状态未知，不是链路断开。
- 地区组在枢纽上选了哪个成员不在链路日志里，看「出口与地区组」页的实际状态（直连拓扑读网关自己，带枢纽的拓扑读当前承载的枢纽）。

字段、上限和更多读法见 [logging.md](../logging.md#链路日志)。

## 能上国内、上不了境外

1. 「概览」看网关是否已安装、宿主执行通道是否正常。
2. 链路日志里主链路当前走哪条腿；所有路径都不通时是失败关闭，境外访问会直接不通（这是设计，不会改走本地宽带）。
3. 「出口与地区组」看默认地区组的实际状态和成员健康。
4. 在网关上 `sudo /usr/local/sbin/meridian-verify.sh`，它核对内核里实际加载的表、规则、标记和兜底表。

## 系统自动更新后不通了

现象：Debian 节点夜里自动更新（unattended-upgrades）后，中继或枢纽不再转发；`ip route show table all` 里 Meridian 的路由表还在，`ip rule` 里 17000–18300 段的规则却没了。

原因：自动更新升级 systemd 时会重启 systemd-networkd。networkd 默认 `ManageForeignRoutingPolicyRules=yes`、`ManageForeignRoutes=yes`，重启时删掉不是它自己建的路由规则和路由，Meridian 的 `ip rule` 就被清掉了。

现在的处理：

- 有 systemd-networkd 的主机上，`meridian-up.sh`（每次安装和开机）和网关的 `install.sh` 写入 `/etc/systemd/networkd.conf.d/90-meridian.conf`（关掉上面两项）。只写文件，**不重启** networkd，它下次启动时生效。撤回时删掉这个文件。
- 网关、中继、枢纽的切换循环每 5 秒检查一次本节点第一条策略规则；连续两次不见就重跑 `meridian-routes.sh` 并重启循环，日志里有一行 `meridian-rule-heal`（`journalctl -u meridian-failover`）。出口节点没有切换循环，只靠上面那个文件。
- 用旧版本装的节点还没有这个文件：预检会报「systemd-networkd 在运行……没有 90-meridian.conf」，重新安装一次即可。

当场恢复：远端节点上 `sudo systemctl restart meridian-node.service`，网关上 `sudo systemctl restart meridian.service`（都是重新执行 `meridian-up.sh`，规则和上面的文件都会补上）。手工补文件也行：

```ini
# /etc/systemd/networkd.conf.d/90-meridian.conf
[Network]
ManageForeignRoutingPolicyRules=no
ManageForeignRoutes=no
```

## 境外网站很慢或卡在一半

多为 MTU：见 [FAQ](faq.md#mtu-怎么定)。另看「出口与地区组」的路径质量，以及是否在 UDP 与 WSS 之间频繁切换（链路日志里的抖动记录）。

## 某个域名走错了出口

在「解析日志」（默认关闭，打开需要确认）或「连接日志」里找这个名字，看它命中了哪条规则或名单、由哪个解析器回答。未列名单的域名默认只经隧道解析（严格模式）；规则和名单的优先级见[架构](../architecture.md)。

## 要回到原状

- 某台设备：把它的网关和 DNS 改回路由器地址。
- 面板版本：[upgrade-rollback.md](upgrade-rollback.md#回滚)。
- 远端节点和网关的数据面：「部署」页的撤回（远端按装机清单撤回，网关撤回到只剩局域网兜底表），见[参考手册](../install-debian13.md)第 9 节。

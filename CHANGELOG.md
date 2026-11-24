# Changelog

Each release has a `## vX.Y.Z` section; the release workflow
(`.github/workflows/release-images.yml`) uses that section as the release
notes and refuses a version without one.

## v1.0.6

- 面板打字更顺手：分流规则、连接日志、解析日志的搜索框不再卡顿；编辑拓扑时输入也更流畅。
- 界面更清爽：标题更轻，卡片和表格改为圆角、柔和阴影；成功、警告、错误提示的底色不再发灰。
- 连接日志的实时连接表更整齐：判断依据收进展开详情，整页只有一个暂停按钮。
- 修复改分流规则后提示「未自动生效」的问题：开启远程接入的网关，规则保存后又能自动生效了。
- 操作反馈更明确：清空日志、修改规则后有提示；删除 Hosts 记录和部署记录前先确认；规则、地区组、服务器编辑框按回车即可提交。
- 出口页各地区默认展开；远端服务器的操作统一叫「下发」，网关叫「安装」，整个流程叫「部署」。

## v1.0.5

- 网关新增 DNS 缓存和 Hosts 管理。
- 连接日志查询更快，可主动断开连接；网关事件触发自动刷新，实时刷新默认开启。
- 正在转发的连接每秒刷新，显示每条连接的实时上传、下载速度和累计流量，可按速度或流量排序。
- 连接日志可从 DHCP 租约和反向 DNS 识别设备名，按手动备注、主机名、IP 的顺序显示。

## v1.0.4

- 受管出口支持保存并自动部署。面板展示逐节点进度、阻断原因、SSH 限流倒计时和自动修复记录。
- 新建的非 NAT 受管 WireGuard 链路可自动分配端口。预检发现自动分配的端口冲突时可换端口并复检，MTU 超过上联承载能力时可采用预检建议值。
- 自动部署可有限重试暂时性 SSH 故障和过期预检。安装结果不明时先复核服务器记录，确认已安装后继续。
- 优化导航、拓扑编辑栏、出口列表和窄屏操作。延迟与丢包分开显示，延迟色块区分较低、中等、较高、过期和无响应。
- 首页网速图支持查看同一时刻的上传和下载。采集暂停时保留历史和空档，国内外累计流量显示可用的起始采样时间。

## v1.0.3

- 重写面板布局和常用操作，加入键盘快速跳转、出口筛选和部署章节导航。
- 首页网速每秒更新，显示最近 60 秒曲线，持久保存国内和境外累计流量。
- 出口显示直连与 Mesh 的当前选择、延迟、丢包和切换原因。双路零丢包时，Mesh 延迟低至少 5% 可触发质量切换。
- 支持已永久退役节点的 Mesh 离线撤回，以及拓扑保存后的自动检测、预检和按序下发。
- 预检可识别旧 Mesh 回程路由残留，自动部署可重试受阻的预检并复用仍有效的结果。
- 名单支持定时更新，关键词无匹配单独展示。编译后的解析路径默认收起。
- 部署页独立显示当前待安装节点和上次应用快照差异，队列为空时提示无待部署节点。

## v1.0.2

- Exits page measures gateway-to-exit TCP handshake latency through the
  selected tunnel, shows results beside region-group members, and labels
  external SOCKS measurements as reaching the carrier resolver.
- Clarifies missing region-group health reports and keeps historical sniff
  targets outside the current monitoring scope out of current alerts.

## v1.0.1

- Lists page shows every rule-set (entries, last update, state, error) with
  per-set and bulk updates; failed rule-set fetches retry after 5/15/60
  minutes instead of waiting a full interval.
- Sniff self-check no longer blocks installs on slow exit resolvers: UDP
  timeout with TCP 53 reachable is a warning, the query timeout is 5 s, and
  a bare SERVFAIL header counts as an answer.
- `install.sh`: picks the panel image from an archive that also carries
  SmartDNS instead of the first image `docker load` lists.

## v1.0.0

First public release.

- Policy rules survive `systemd-networkd` restarts (e.g. a systemd upgrade by
  unattended-upgrades): nodes and the gateway get a networkd drop-in, failover
  loops re-install missing rules, preflight warns when the drop-in is missing.
- DNS journal no longer loses records when a rotated audit file's inode is
  reused.
- SSH through a relay: a refusal sent before the version exchange is read and
  reported as rate limiting instead of an early close.
- One-command gateway install (`deploy/debian/install.sh`): prebuilt image by
  version, image archive or local build; management firewall for the panel
  port (IPv4/IPv6, Docker port rules); safe to re-run.
- One-command upgrade and rollback (`deploy/debian/upgrade.sh`,
  `deploy/debian/rollback.sh`) with volume backups and automatic rollback on a
  failed health check; `deploy/debian/api.sh` for API calls from the gateway.
- Multi-arch (amd64/arm64) image workflow definition, manual and build-only by
  default.

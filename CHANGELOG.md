# Changelog

Each release has a `## vX.Y.Z` section; the release workflow
(`.github/workflows/release-images.yml`) uses that section as the release
notes and refuses a version without one.

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

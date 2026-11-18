# HEAD 391aa50 审查基线与后续审查矩阵（T1）

源版本：`391aa50c05d2b8e444875c08bd8bc3766922ef3b`。起始工作区干净。
本文件是编码交接记录，不是验证结论或部署批准。未改生产代码、既有 golden、Git 状态或 Concord 状态；未联网或访问真实主机。

## T1 交付范围（修订 3）

按用户修订 3，T1 交付编译基线、审查矩阵、提案四类缺陷的静态复核与切换失败契约；不修改生产代码。未查清项不阻止本步交付，必须按下表及逐文件负责人交给 T2–T6。此处交付的是后续工作的明确边界，不表示全库安全审查已完成。T6 须对所有剩余项给出结论或列为需人类决定的建议，不能静默遗漏。

## 已冻结的基线

在生产代码修改前，以本 checkout 的 HEAD 编译器生成。`baseline.sha256` 记录全部五份既有 `.golden` 原文件的 SHA-256、固定输入和完整基线 JSON 的摘要；没有重写既有 golden。

`baseline-bundles.json` 的 `files` 保存每个编译产物的原始字节（JSON 的 base64 字段，解码后无换行或编码归一化）及 SHA-256，`apply_order` 保存应用顺序，`topology_sha256` 固定输入原文件。包含占位凭据，不含真实密钥。

输入 `internal/compile/testdata/review_topology.json` 固定覆盖无 IX、NAT 主中继 access → 主枢纽 hka、两台备用中继经 `wg_over_wss` → 备用枢纽 hkb、7 出口、NAT 拨出出口以及 hka → dc7 的 Mesh 备用腿。网关到三个中继均为 `udp_wss_failover`。NAT 中继以合成公网端口映射端点表示；编译器没有模拟 NAT 转发设备，该输入不能证明 NAT 转发可达。hka/hkb 的旧式 SSH 字段表示经中继 TCP 端口映射的管理目标，**没有**运行凭据迁移或 SSH 跳转执行链，不能据此宣称管理回程已查清。

基线文件数量：267；应用顺序：dc2 → dc1 → dc3 → dc4 → dc5 → dc6 → dc7 → hka → hkb → access → bk1 → bk2 → gw。

（T3，2026-11-18：输入与基线做过一次纯数据去名——节点 ID、局域网网段（改为 192.0.2.0/24）、WSS 端口（改为 8444）和节点名按统一映射换成合成值。基线字节按同一映射改写后重算摘要，`t2-accepted.json` 的三份网关脚本摘要随之更新；改写前用临时等价测试证明：对每个示例，「旧输入的编译产物经映射」与「映射后输入的编译产物」逐字节相同，只差脚本里对内容求的哈希（SH_VERSION、GROUP_PLAN）。见 `docs/privacy-inventory.md`「T3 处理结果」。）

`TestReviewTopologyBaseline` 读取固定输入，对全部产物字节、文件集合、摘要和顺序进行比较；没有自动更新模式。任何后续必要变化必须关联确认缺陷、逐文件解释，并保留本轮原始基线。

## 实施前切换契约（T2 必须满足）

1. 观测、候选决策与已应用状态分离。测量可更新，目标组、承载接口、权重、成功标记、`since`、`LastSwitch` 和 fallback 同步状态必须仅在 nft 与全部 IPv4/IPv6 路由操作成功后发布。失败状态显示错误，同时保留最后成功路径及其时间。
2. 任一路由或 nft 命令失败均向上传播；不能由后续成功命令覆盖。失败不得写 `SH_APPLIED`，不得将目标作为 fallback 的承载组，也不得启动一条绕过错误的替代切换。
3. 切换前保存上一份**成功应用**的 nft 与 IPv4/IPv6 路由快照，绑定同一配置版本和操作代次；不能拿候选配置或部分失败后的现场作成功快照。补偿仅恢复此快照，或在尚未修改数据面时保持原路径。禁止直连/default 主路由绕过、清空拒绝规则或关闭 IPv6 保护。
4. 补偿期间保留拒绝保护，直到上一成功路径的 nft 与路由均恢复。仅在补偿全部成功后可报告恢复到上一成功路径；错误本身仍须可见。不能以补偿成功冒充目标切换成功。
5. 没有可信成功快照，或补偿任一步失败：进入显式恢复阻塞状态，保留拒绝保护/黑洞保护，报告承载未知或不可用（最后成功记录仅作历史，不能声称当前健康）。禁止后续自动危险切换、禁止写成功标记；由显式人工恢复或完整重新安装、重新校验并建立成功快照后解除阻塞。
6. 一次尝试至多执行一次补偿，不无限重试；应用拒绝或部分失败不能每个五秒循环重试危险修改。重试需有有限次数、明确退避、配置/代次校验；恢复阻塞不能被控制器重启绕过。
7. 必须逐条注入 nft 拒绝、各 IPv4/IPv6 路由失败、状态发布失败、首次无快照、补偿失败、重启及重试，断言无成功标记/时间推进/目标组发布，且保护始终存在。纯 shell 桩只能证明控制流，隔离数据面证据另记。

## 对提案四类问题的 HEAD 复核与任务分配

以下为静态代码证据。本轮未重新执行提案原始故障桩，不冒称新动态复现。

| 缺陷 | 具体代码与因果证据 | 复现条件 | 后续任务 |
| --- | --- | --- | --- |
| P1 路由失败被覆盖 | `internal/compile/share.go:367` 的 `share_table_route`、`share_designate` 没有逐命令错误传播；`share_apply` 先应用 nft，再循环路由；`share_once` 仅依赖最终返回值写标记 | 令早期 IPv4 或 IPv6 route replace 失败、后续命令成功；nft 已更新，函数仍可成功，随后写 `SH_APPLIED` | T2：逐命令传播、成功快照补偿、失败关闭 |
| P1 状态提前发布 | `internal/pathquality/run.go:117` 在 stdout 决策送给 shell 前写 state/status；`quality.go:1154` 已推进切换时间；`share_groups.go` 的 `share_fallback_step` 提前改 `fb_up/fb_switched`，末尾 `share_once ... || true` 后仍 `share_record`；`share.go` 非分组 fallback 同样忽略应用失败 | 先生成主→备决策，再令 nft 拒绝；或 fallback 路径令 `share_once` 失败，观察状态/时间与实际路径不符 | T2：统一成功发布契约，覆盖分组及非分组 fallback |
| P2 重启遗留 scheduled | `internal/api/rules_autoapply.go:197` 的 timer/base 只在内存；`:337` 注册 timer，随后 `recordRulesLast` 持久化 scheduled；`:558` pending 仅看内存。`web/src/ui_base.tsx:783` 排除 scheduled 为终态，达到 60 次后不改显示 | 连续保存进入 scheduled，timer 触发前退出并重启进程；GET 返回 pending=false、last=scheduled；前端约三分钟后仍显示将自动生效 | T4：标记中断/需安装，不绕过重校验恢复；轮询超时待确认 |
| P2 解锁轮询响应乱序 | `web/src/UnlockPage.tsx:230` 的异步 setInterval 每两秒启动请求；清理只取消 interval，无请求取消、串行化或代次校验 | 一次 running 响应延迟超过两秒，晚于完成响应返回；旧响应覆盖完成状态。卸载或重探测时旧请求仍能回写 | T5：完成后调度、AbortSignal、代次保护 |

尚未确认其他缺陷。T3 负责白名单/事务/宿主执行，T5 同时负责推荐→采用→路由一致性，T6 负责后续审查确认的其余缺陷与兼容差异；每个新缺陷必须有具体复现条件后才能分配，不能将猜测写为缺陷。

## 风险审查矩阵与后续负责人

“未查清”表示仍需代码追踪及合成故障证据，不表示确认存在缺陷。下列路径是后续审查入口，不冒称已阅读或验证；逐文件清单补充全库覆盖责任。跨领域由表内任务主责，T6 收尾核对。

| 范围 | 现有证据/代码入口 | 结论与待查项 | 负责人 |
| --- | --- | --- | --- |
| 编译字节与拓扑覆盖 | review_topology_test.go、固定输入、267 文件原字节及五份 golden 摘要 | 基线已冻结；合成映射不能证明 NAT 转发或管理可达 | T6：最终兼容差异；T3：管理执行链 |
| 运行时主备/分担 | compile/share.go、share_groups.go、pathquality/run.go、quality.go 的上述静态证据 | 两类 P1 已确认；初始化、分组/非分组 fallback、快照、补偿和重启阻塞待查 | T2 |
| 自动安装白名单/并发 | api/rules_autoapply.go、autoapply.go、store/store.go | scheduled 重启遗留已确认；白名单闭包、版本绑定、同锁快照及并发保存待查 | T3：安装边界；T4：重启状态 |
| 事务崩溃恢复 | apply/txn.go、apply.go、peersync.go、api/deploy_plan.go | 未查清：各阶段崩溃点、幂等性、锁、补偿失败、启动恢复及部分节点成功 | T3 |
| 宿主固定动作/凭据/路径权限 | hostexec/hostexec.go、peercred_linux.go、restore.go、apply/secret.go、sshexec/、provision/ | 未查清：命令注入、对端认证、固定动作参数、路径穿越/符号链接、权限及输出脱敏 | T3 |
| 经中继管理与无 IX 部署 | api/mgmt_candidates.go、ssh_ops.go、model/nested.go、validate/reachability.go、sshexec/channel.go | 未查清：NAT 映射、跳转凭据迁移、回程、备用枢纽经中继管理及失败恢复 | T3 |
| 预检 | preflight/evaluate.go、script.go、api/preflight.go、mesh/deployment_preflight.go | 未查清：警告确认、拒绝边界、目标/配置版本/bundle 绑定、检查失败处理 | T3 |
| DNS/IPv6/直连绕过 | compile/render_nft.go、render_routes.go、render_dns.go、validate/、verify/、deploy/verify-* | 生成文本仅为基线；失败场景、冷启动、切换、Mesh、回程和 DNS 不回落仍需隔离数据面证据 | T6；切换失败控制流由 T2 负责 |
| 解锁推荐→采用→路由 | api/unlock_matrix.go、unlock_routing.go、unlock/、probe/、UnlockPage.tsx | 轮询乱序已确认；eligibility、identity、地区/出口一致性、过期结果与实际采用待查 | T5 |
| 自动安装前端终态 | ui_base.tsx RulesApplyLine、rules_apply_line.test.tsx | scheduled 轮询耗尽缺少待确认终态；取消、重启、错误恢复待覆盖 | T4 |
| 其余前端关键页及日志导航 | App.tsx、DeployPage.tsx、RulesPage.tsx、OverviewPage.tsx、RemotePage.tsx、各 LogsPage、api.ts | 未查清：状态陈旧、操作竞态、取消、恢复入口、无障碍标签和旧日志路由兼容 | T6 |
| 定时器/轮询/goroutine/日志增长 | pathquality/measure.go、api/traffic.go、linkjournal/、dnsjournal/、sniff/、sshexec/pool.go、各前端 effect | 两项已知调度/轮询问题外，任务退出、超时、连接池、日志保留/容量及后台资源上界未查清 | T6；T4/T5 分别负责所属轮询 |
| 其余模型、规则、部署脚本、文档/构建 | 下方全库清单 | 未查清：规则优先级、输入校验、兼容及过时文案；不执行网络脚本 | T6 |

## 仅供人类决定的优化

| 问题 | 收益 | 代价 | 风险 |
| --- | --- | --- | --- |
| Go 决策和 shell fallback 各维护状态机 | 统一模型可减少发布时序偏差 | 控制器接口和兼容迁移较大 | 旧二进制 fallback/启动兼容；本轮不实施 |
| 多节点安装需要跨节点一致性设计 | 可明确部分安装与恢复边界 | 需要独立事务协议及恢复方案 | 管理通道中断时可用性；本轮不实施 |
| 视觉和文案清理 | 简化关键操作、降低认知负担 | 需逐页面确认恢复入口与无障碍标签 | 隐藏错误/日志入口；本轮不实施 |

## HEAD 全库文件清单与逐文件审查状态

下表由只读 `git ls-files` 取得，排除 Git 内部状态；列出 HEAD 的全部跟踪文件（含隐藏配置）。列入清单不等于读过。`局部证据` 仅指上述具体路径，**不是整个文件已查清**；其余均明确未查清。每项标注主责；跨领域按上方矩阵拆分，T6 对剩余项负责收尾。本轮新增文件列在本节之后。

| 文件 | 状态 |
| --- | --- |
| `.dockerignore` | 未查清；T6（跨领域按上表） |
| `.github/workflows/ci.yml` | 未查清；T6（跨领域按上表） |
| `.gitignore` | 未查清；T6（跨领域按上表） |
| `LICENSE` | 未查清；T6（跨领域按上表） |
| `Makefile` | 未查清；T6（跨领域按上表） |
| `README.md` | 未查清；T6（跨领域按上表） |
| `cmd/meridian/main.go` | 未查清；T6（跨领域按上表） |
| `cmd/meridian/sniffverify.go` | 未查清；T6（跨领域按上表） |
| `cmd/meridian/sniffverify_test.go` | 未查清；T6（跨领域按上表） |
| `deploy/Dockerfile` | 未查清；T6（跨领域按上表） |
| `deploy/artifacts/.gitignore` | 未查清；T6（跨领域按上表） |
| `deploy/artifacts/README.md` | 未查清；T6（跨领域按上表） |
| `deploy/debian/install.sh` | 未查清；T6（跨领域按上表） |
| `deploy/debian/meridian-guard.service` | 未查清；T6（跨领域按上表） |
| `deploy/debian/meridian-host.service` | 未查清；T6（跨领域按上表） |
| `deploy/debian/meridian.service` | 未查清；T6（跨领域按上表） |
| `deploy/docker-compose.yml` | 未查清；T6（跨领域按上表） |
| `deploy/fetch-artifacts.sh` | 未查清；T6（跨领域按上表） |
| `deploy/verify-host-exec.sh` | 未查清；T6（跨领域按上表） |
| `deploy/verify-mesh-veth.sh` | 未查清；T6（跨领域按上表） |
| `deploy/verify-smartdns.sh` | 未查清；T6（跨领域按上表） |
| `deploy/verify-sniff-systemd.sh` | 未查清；T6（跨领域按上表） |
| `design-system/meridian/MASTER.md` | 未查清；T6（跨领域按上表） |
| `docs/architecture.md` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-12-debian13/README.md` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-12-debian13/meridian-verify.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-12-debian13/mesh-veth.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-12-debian13/netns-reload.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-12-debian13/verify-host-exec-boot.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-12-debian13/verify-host-exec.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-12-debian13/verify-smartdns.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13-dual-hub/README.md` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13-dual-hub/netns-dual-hub.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13-dual-hub/netns-group-dns.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13-dual-hub/netns-reload.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13-dual-hub/netns-ula-lan.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13-mesh-dns/README.md` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13-mesh-dns/netns-group-dns.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13-mesh-dns/netns-reload.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13-mesh-dns/netns-ula-lan.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13/README.md` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13/meridian-verify-after-reboot.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13/meridian-verify.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13/mesh-veth.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13/netns-group-dns.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13/netns-reload.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13/netns-ula-lan.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13/verify-host-exec-boot.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13/verify-host-exec.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-13-debian13/verify-smartdns.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-16-netns-endpoint-access/README.md` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-16-netns-endpoint-access/netns-endpoint-access-mutant.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-16-netns-endpoint-access/netns-endpoint-access.log` | 未查清；T6（跨领域按上表） |
| `docs/evidence/2026-11-16-netns-mesh-leg/netns-mesh-leg.log` | 未查清；T6（跨领域按上表） |
| `docs/install-debian13.md` | 未查清；T6（跨领域按上表） |
| `docs/logging.md` | 未查清；T6（跨领域按上表） |
| `docs/mihomo-import.md` | 未查清；T6（跨领域按上表） |
| `docs/remote-access.md` | 未查清；T6（跨领域按上表） |
| `docs/test-device.md` | 未查清；T6（跨领域按上表） |
| `docs/ui-layout.md` | 未查清；T6（跨领域按上表） |
| `docs/unlock-methods.md` | 未查清；T6（跨领域按上表） |
| `docs/verification.md` | 未查清；T6（跨领域按上表） |
| `examples/topology.example.json` | 未查清；T6（跨领域按上表） |
| `go.mod` | 未查清；T6（跨领域按上表） |
| `go.sum` | 未查清；T6（跨领域按上表） |
| `internal/acceptance/acceptance_test.go` | 未查清；T6（跨领域按上表） |
| `internal/acceptance/catalog.go` | 未查清；T6（跨领域按上表） |
| `internal/acceptance/store.go` | 未查清；T6（跨领域按上表） |
| `internal/api/acceptance.go` | 未查清；T6（跨领域按上表） |
| `internal/api/acceptance_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/allocations.go` | 未查清；T6（跨领域按上表） |
| `internal/api/allocations_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/apply_codes_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/artifacts.go` | 未查清；T6（跨领域按上表） |
| `internal/api/artifacts_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/autoapply.go` | 未查清；T6（跨领域按上表） |
| `internal/api/autoapply_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/demo_fixtures_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/deploy_plan.go` | 未查清；T6（跨领域按上表） |
| `internal/api/deploy_plan_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/deploy_skip.go` | 未查清；T6（跨领域按上表） |
| `internal/api/deploy_verify.go` | 未查清；T6（跨领域按上表） |
| `internal/api/deploy_verify_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/dns.go` | 未查清；T6（跨领域按上表） |
| `internal/api/dns_journal.go` | 未查清；T6（跨领域按上表） |
| `internal/api/dns_journal_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/dns_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/dns_version.go` | 未查清；T6（跨领域按上表） |
| `internal/api/dns_version_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/dualhub_runtime_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/e2e_flow_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/endpoint_access_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/exit_identity.go` | 未查清；T6（跨领域按上表） |
| `internal/api/keyword_state.go` | 未查清；T6（跨领域按上表） |
| `internal/api/keyword_state_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/link_journal.go` | 未查清；T6（跨领域按上表） |
| `internal/api/link_journal_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/listen.go` | 未查清；T6（跨领域按上表） |
| `internal/api/listen_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/lists.go` | 未查清；T6（跨领域按上表） |
| `internal/api/lists_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/mesh.go` | 未查清；T6（跨领域按上表） |
| `internal/api/mesh_hosts.go` | 未查清；T6（跨领域按上表） |
| `internal/api/mesh_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/mgmt_candidates.go` | 未查清；T6（跨领域按上表） |
| `internal/api/mgmt_candidates_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/node_state.go` | 未查清；T6（跨领域按上表） |
| `internal/api/node_state_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/noix_deploy_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/phase23.go` | 未查清；T6（跨领域按上表） |
| `internal/api/preflight.go` | 未查清；T6（跨领域按上表） |
| `internal/api/preflight_api_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/preflight_files_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/provision_api.go` | 未查清；T6（跨领域按上表） |
| `internal/api/region_group_refs_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/region_groups.go` | 未查清；T6（跨领域按上表） |
| `internal/api/region_groups_runtime.go` | 未查清；T6（跨领域按上表） |
| `internal/api/region_groups_runtime_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/region_groups_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/relaybackup_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/remote_access.go` | 未查清；T6（跨领域按上表） |
| `internal/api/remote_access_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/remote_fast.go` | 未查清；T6（跨领域按上表） |
| `internal/api/remote_fast_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/resources.go` | 未查清；T6（跨领域按上表） |
| `internal/api/resources_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/rules_autoapply.go` | 局部证据，余项未查清；T4（安装安全边界 T3） |
| `internal/api/rules_autoapply_test.go` | 未查清；T4（安装安全边界 T3） |
| `internal/api/rules_import.go` | 未查清；T6（跨领域按上表） |
| `internal/api/rules_import_more_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/rules_import_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/rulesets.go` | 未查清；T6（跨领域按上表） |
| `internal/api/rulesets_auth.go` | 未查清；T6（跨领域按上表） |
| `internal/api/rulesets_auth_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/secrets_seams_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/server.go` | 未查清；T6（跨领域按上表） |
| `internal/api/server_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/sharing.go` | 未查清；T6（跨领域按上表） |
| `internal/api/sharing_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/sniff.go` | 未查清；T6（跨领域按上表） |
| `internal/api/sniff_diag.go` | 未查清；T6（跨领域按上表） |
| `internal/api/sniff_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/socks_version.go` | 未查清；T6（跨领域按上表） |
| `internal/api/socks_version_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/ssh_ops.go` | 未查清；T6（跨领域按上表） |
| `internal/api/ssh_ops_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/static.go` | 未查清；T6（跨领域按上表） |
| `internal/api/static_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/status.go` | 未查清；T6（跨领域按上表） |
| `internal/api/status_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/testdata/pre-redesign-topology.json` | 未查清；T6（跨领域按上表） |
| `internal/api/topology_contract.go` | 未查清；T6（跨领域按上表） |
| `internal/api/topology_contract_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/traffic.go` | 未查清；T6（跨领域按上表） |
| `internal/api/traffic_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/unlock_identity_egress_test.go` | 未查清；T5 |
| `internal/api/unlock_identity_test.go` | 未查清；T5 |
| `internal/api/unlock_manual_test.go` | 未查清；T5 |
| `internal/api/unlock_matrix.go` | 未查清；T5 |
| `internal/api/unlock_matrix_test.go` | 未查清；T5 |
| `internal/api/unlock_probe.go` | 未查清；T5 |
| `internal/api/unlock_probe_test.go` | 未查清；T5 |
| `internal/api/unlock_routing.go` | 未查清；T5 |
| `internal/api/unlock_routing_test.go` | 未查清；T5 |
| `internal/api/upgrade_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/uplink_mtu.go` | 未查清；T6（跨领域按上表） |
| `internal/api/uplink_mtu_carry_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/upstream.go` | 未查清；T6（跨领域按上表） |
| `internal/api/withdraw.go` | 未查清；T6（跨领域按上表） |
| `internal/api/withdraw_test.go` | 未查清；T6（跨领域按上表） |
| `internal/api/wss.go` | 未查清；T6（跨领域按上表） |
| `internal/api/wss_test.go` | 未查清；T6（跨领域按上表） |
| `internal/apply/apply.go` | 未查清；T3 |
| `internal/apply/apply_test.go` | 未查清；T3 |
| `internal/apply/artifacts.go` | 未查清；T3 |
| `internal/apply/artifacts_test.go` | 未查清；T3 |
| `internal/apply/lock_other.go` | 未查清；T3 |
| `internal/apply/lock_unix.go` | 未查清；T3 |
| `internal/apply/peersync.go` | 未查清；T3 |
| `internal/apply/peersync_test.go` | 未查清；T3 |
| `internal/apply/secret.go` | 未查清；T3 |
| `internal/apply/sniff_selfcheck_test.go` | 未查清；T3 |
| `internal/apply/sniff_test.go` | 未查清；T3 |
| `internal/apply/sysctl.go` | 未查清；T3 |
| `internal/apply/sysctl_test.go` | 未查清；T3 |
| `internal/apply/txn.go` | 未查清；T3 |
| `internal/apply/txn_test.go` | 未查清；T3 |
| `internal/apply/withdraw.go` | 未查清；T3 |
| `internal/apply/withdraw_test.go` | 未查清；T3 |
| `internal/artifacts/artifacts.lock` | 未查清；T6（跨领域按上表） |
| `internal/artifacts/bundle.go` | 未查清；T6（跨领域按上表） |
| `internal/artifacts/bundle_test.go` | 未查清；T6（跨领域按上表） |
| `internal/artifacts/catalog.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/allocations.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/carry_mtu_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/coexist_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/compile.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/compile_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/decide_snapshot_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/decision_files.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/dial_egress_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/dns_log_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/dns_policy_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/dns_settings_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/dns_view.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/dualhub_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/empty_operand.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/endpoint_access_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/external_exit_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/external_real_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/gateway_round2_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/golden_single_hub_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/group_dns_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/groups_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/hub_state.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/hub_state_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/leak_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/legacy_services_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/link_log_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/linkless_node_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/local_mss_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/mesh_backup_hub_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/mesh_quality.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/mesh_quality_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/mesh_transport.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/mesh_transport_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/mgmt_reach.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/mgmt_reach_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/mtu_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_dual_hub_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_endpoint_access_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_external_exit_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_fwcompat_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_group_dns_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_link_journal_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_live_mtu_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_mesh_leg_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_mss_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_nested_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_relay_quality_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_reload_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_sniff_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_sniff_wg_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/netns_uplink_mtu_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/noix_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/ordered_nft_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/ordered_real_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/ordered_rules_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/phase23_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/plan.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/policy.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/probe_targets.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/relay_speedtest.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/relay_speedtest_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/relaybackup_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/remote_access.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/remote_access_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_coexist.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_dns.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_dnslog.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_dualhub.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_linklog.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_nested.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_nft.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_node.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_phase23.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_routes.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/render_sniff.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/rule_change.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/rule_change_group_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/rule_change_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/service_select_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/share.go` | 局部证据，余项未查清；T2 |
| `internal/compile/share_groups.go` | 局部证据，余项未查清；T2 |
| `internal/compile/share_test.go` | 未查清；T2 |
| `internal/compile/smartdns_audit_real_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/smartdns_exit_upstream_real_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/smartdns_real_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/sniff_selfcheck_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/sniff_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/sniff_units_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/testdata/noix_example.golden` | 未查清；T6（跨领域按上表） |
| `internal/compile/testdata/relay_backup_example.golden` | 未查清；T6（跨领域按上表） |
| `internal/compile/testdata/single_hub_example.golden` | 未查清；T6（跨领域按上表） |
| `internal/compile/testdata/single_hub_groupdns.golden` | 未查清；T6（跨领域按上表） |
| `internal/compile/testdata/single_hub_remote_access.golden` | 未查清；T6（跨领域按上表） |
| `internal/compile/traffic_counters_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/tunnel.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/tunnel_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/ula_lan_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/upstream.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/verify_script_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/verify_sniff_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/wss.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/wss_test.go` | 未查清；T6（跨领域按上表） |
| `internal/compile/wstunnel_real_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/dns.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/dns_test.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/ruleset_auth.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/ruleset_auth_test.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/socks.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/socks_test.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/store.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/store_test.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/wireguard.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/wss.go` | 未查清；T6（跨领域按上表） |
| `internal/credentials/wss_test.go` | 未查清；T6（跨领域按上表） |
| `internal/defaults/defaults.go` | 未查清；T6（跨领域按上表） |
| `internal/defaults/dualhub.go` | 未查清；T6（跨领域按上表） |
| `internal/defaults/nested.go` | 未查清；T6（跨领域按上表） |
| `internal/defaults/noix.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/daemon.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/daemon_test.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/gate.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/journal.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/journal_test.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/parser.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/parser_test.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/sink.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/tail.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/tail_test.go` | 未查清；T6（跨领域按上表） |
| `internal/dnsjournal/verify_script_test.go` | 未查清；T6（跨领域按上表） |
| `internal/dnssplit/dnssplit.go` | 未查清；T6（跨领域按上表） |
| `internal/dnssplit/dnssplit_test.go` | 未查清；T6（跨领域按上表） |
| `internal/dnssplit/mark_linux.go` | 未查清；T6（跨领域按上表） |
| `internal/dnssplit/mark_other.go` | 未查清；T6（跨领域按上表） |
| `internal/dnssplit/stats.go` | 未查清；T6（跨领域按上表） |
| `internal/hostexec/acceptance.go` | 未查清；T3 |
| `internal/hostexec/acceptance_test.go` | 未查清；T3 |
| `internal/hostexec/disk_other.go` | 未查清；T3 |
| `internal/hostexec/disk_unix.go` | 未查清；T3 |
| `internal/hostexec/dns.go` | 未查清；T3 |
| `internal/hostexec/dns_journal.go` | 未查清；T3 |
| `internal/hostexec/dns_journal_test.go` | 未查清；T3 |
| `internal/hostexec/dns_test.go` | 未查清；T3 |
| `internal/hostexec/hostexec.go` | 未查清；T3 |
| `internal/hostexec/hostexec_test.go` | 未查清；T3 |
| `internal/hostexec/link_journal.go` | 未查清；T3 |
| `internal/hostexec/link_journal_test.go` | 未查清；T3 |
| `internal/hostexec/lists.go` | 未查清；T3 |
| `internal/hostexec/lists_test.go` | 未查清；T3 |
| `internal/hostexec/peercred_linux.go` | 未查清；T3 |
| `internal/hostexec/peercred_other.go` | 未查清；T3 |
| `internal/hostexec/preflight.go` | 未查清；T3 |
| `internal/hostexec/preflight_test.go` | 未查清；T3 |
| `internal/hostexec/probe.go` | 未查清；T3 |
| `internal/hostexec/probe_test.go` | 未查清；T3 |
| `internal/hostexec/remote_access.go` | 未查清；T3 |
| `internal/hostexec/remote_access_test.go` | 未查清；T3 |
| `internal/hostexec/restore.go` | 未查清；T3 |
| `internal/hostexec/restore_test.go` | 未查清；T3 |
| `internal/hostexec/smartdns_reload.go` | 未查清；T3 |
| `internal/hostexec/smartdns_reload_test.go` | 未查清；T3 |
| `internal/hostexec/sniff.go` | 未查清；T3 |
| `internal/hostexec/sniff_test.go` | 未查清；T3 |
| `internal/hostexec/sniffcheck_test.go` | 未查清；T3 |
| `internal/hostexec/traffic.go` | 未查清；T3 |
| `internal/hostexec/traffic_conns.go` | 未查清；T3 |
| `internal/hostexec/traffic_conns_test.go` | 未查清；T3 |
| `internal/hostexec/traffic_test.go` | 未查清；T3 |
| `internal/hostexec/upstream.go` | 未查清；T3 |
| `internal/hostexec/upstream2.go` | 未查清；T3 |
| `internal/hostexec/upstream2_test.go` | 未查清；T3 |
| `internal/hostexec/upstream_test.go` | 未查清；T3 |
| `internal/hostexec/wgstatus.go` | 未查清；T3 |
| `internal/hostexec/wgstatus_test.go` | 未查清；T3 |
| `internal/hubstate/hubstate.go` | 未查清；T6（跨领域按上表） |
| `internal/hubstate/hubstate_test.go` | 未查清；T6（跨领域按上表） |
| `internal/linkjournal/daemon.go` | 未查清；T6（跨领域按上表） |
| `internal/linkjournal/daemon_test.go` | 未查清；T6（跨领域按上表） |
| `internal/linkjournal/journal.go` | 未查清；T6（跨领域按上表） |
| `internal/linkjournal/journal_test.go` | 未查清；T6（跨领域按上表） |
| `internal/linkjournal/sources.go` | 未查清；T6（跨领域按上表） |
| `internal/linkjournal/sources_test.go` | 未查清；T6（跨领域按上表） |
| `internal/lists/derive.go` | 未查清；T6（跨领域按上表） |
| `internal/lists/lists.go` | 未查清；T6（跨领域按上表） |
| `internal/lists/lists_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/backup_hub_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/cloudflare.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/connector.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/connector_stub_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/connector_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/creds.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/defaultroutes_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/deploy.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/deploy_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/deployment_preflight.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/hostmesh.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/lifecycle.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/lifecycle_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/mesh.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/mesh_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/permissions.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/r1_blockers_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/remote.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/reuse_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/rulescan_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/upgrade_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/warp_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mesh/withdraw_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mihomo/ai_us_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mihomo/import.go` | 未查清；T6（跨领域按上表） |
| `internal/mihomo/import_test.go` | 未查清；T6（跨领域按上表） |
| `internal/mihomo/parse.go` | 未查清；T6（跨领域按上表） |
| `internal/model/dnslog.go` | 未查清；T6（跨领域按上表） |
| `internal/model/groups.go` | 未查清；T6（跨领域按上表） |
| `internal/model/hubs.go` | 未查清；T6（跨领域按上表） |
| `internal/model/legacy_services.go` | 未查清；T6（跨领域按上表） |
| `internal/model/link_allocations.go` | 未查清；T6（跨领域按上表） |
| `internal/model/link_allocations_test.go` | 未查清；T6（跨领域按上表） |
| `internal/model/mesh.go` | 未查清；T6（跨领域按上表） |
| `internal/model/model.go` | 未查清；T6（跨领域按上表） |
| `internal/model/nested.go` | 未查清；T6（跨领域按上表） |
| `internal/model/pathquality.go` | 未查清；T6（跨领域按上表） |
| `internal/model/pathquality_test.go` | 未查清；T6（跨领域按上表） |
| `internal/model/remote_access.go` | 未查清；T6（跨领域按上表） |
| `internal/model/rules.go` | 未查清；T6（跨领域按上表） |
| `internal/model/sniff.go` | 未查清；T6（跨领域按上表） |
| `internal/model/wss.go` | 未查清；T6（跨领域按上表） |
| `internal/mtu/mtu.go` | 未查清；T6（跨领域按上表） |
| `internal/mtu/mtu_test.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/analysis.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/derive.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/engine.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/engine_test.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/entries.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/exclude.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/exclude_test.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/gateway.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/keyword_note.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/ordered.go` | 未查清；T6（跨领域按上表） |
| `internal/ordered/ordered_test.go` | 未查清；T6（跨领域按上表） |
| `internal/pathquality/config.go` | 未查清；T2 |
| `internal/pathquality/groups_test.go` | 未查清；T2 |
| `internal/pathquality/measure.go` | 未查清；T2 |
| `internal/pathquality/mesh.go` | 未查清；T2 |
| `internal/pathquality/mesh_test.go` | 未查清；T2 |
| `internal/pathquality/proc_other.go` | 未查清；T2 |
| `internal/pathquality/proc_unix.go` | 未查清；T2 |
| `internal/pathquality/qos.go` | 未查清；T2 |
| `internal/pathquality/qos_test.go` | 未查清；T2 |
| `internal/pathquality/quality.go` | 未查清；T2 |
| `internal/pathquality/quality_test.go` | 未查清；T2 |
| `internal/pathquality/run.go` | 局部证据，余项未查清；T2 |
| `internal/pathquality/speedtest.go` | 未查清；T2 |
| `internal/pathquality/speedtest_linux.go` | 未查清；T2 |
| `internal/pathquality/speedtest_other.go` | 未查清；T2 |
| `internal/pathquality/speedtest_test.go` | 未查清；T2 |
| `internal/pathquality/status.go` | 未查清；T2 |
| `internal/pool/pool.go` | 未查清；T6（跨领域按上表） |
| `internal/pool/pool_test.go` | 未查清；T6（跨领域按上表） |
| `internal/preflight/coexist_test.go` | 未查清；T3 |
| `internal/preflight/evaluate.go` | 未查清；T3 |
| `internal/preflight/external_test.go` | 未查清；T3 |
| `internal/preflight/footprint.go` | 未查清；T3 |
| `internal/preflight/ixhub_test.go` | 未查清；T3 |
| `internal/preflight/nolink.go` | 未查清；T3 |
| `internal/preflight/nolink_test.go` | 未查清；T3 |
| `internal/preflight/preflight_test.go` | 未查清；T3 |
| `internal/preflight/report.go` | 未查清；T3 |
| `internal/preflight/script.go` | 未查清；T3 |
| `internal/preflight/testdata/clean-debian13.txt` | 未查清；T3 |
| `internal/preflight/testdata/debian12.txt` | 未查清；T3 |
| `internal/preflight/testdata/docker-forward-drop.txt` | 未查清；T3 |
| `internal/preflight/testdata/existing-wireguard.txt` | 未查清；T3 |
| `internal/preflight/testdata/gateway-installed.txt` | 未查清；T3 |
| `internal/preflight/testdata/ports-taken.txt` | 未查清；T3 |
| `internal/preflight/testdata/ubuntu2004-arm64.txt` | 未查清；T3 |
| `internal/preflight/testdata/warp.txt` | 未查清；T3 |
| `internal/probe/adapters.go` | 未查清；T5 |
| `internal/probe/adapters_more.go` | 未查清；T5 |
| `internal/probe/adapters_more_test.go` | 未查清；T5 |
| `internal/probe/adapters_new.go` | 未查清；T5 |
| `internal/probe/adapters_test.go` | 未查清；T5 |
| `internal/probe/body_limit_test.go` | 未查清；T5 |
| `internal/probe/coverage.go` | 未查清；T5 |
| `internal/probe/disabled_ai_test.go` | 未查清；T5 |
| `internal/probe/mark_linux.go` | 未查清；T5 |
| `internal/probe/mark_other.go` | 未查清；T5 |
| `internal/probe/pinned.go` | 未查清；T5 |
| `internal/probe/pinned_test.go` | 未查清；T5 |
| `internal/probe/probe.go` | 未查清；T5 |
| `internal/probe/probe_test.go` | 未查清；T5 |
| `internal/probe/scope.go` | 未查清；T5 |
| `internal/probe/scope_test.go` | 未查清；T5 |
| `internal/provision/coexist_test.go` | 未查清；T3 |
| `internal/provision/nested_test.go` | 未查清；T3 |
| `internal/provision/procgroup_other_test.go` | 未查清；T3 |
| `internal/provision/procgroup_unix_test.go` | 未查清；T3 |
| `internal/provision/provision.go` | 未查清；T3 |
| `internal/provision/provision_test.go` | 未查清；T3 |
| `internal/provision/withdraw.go` | 未查清；T3 |
| `internal/provision/withdraw_test.go` | 未查清；T3 |
| `internal/provision/wss_test.go` | 未查清；T3 |
| `internal/remoteaccess/remoteaccess.go` | 未查清；T6（跨领域按上表） |
| `internal/remoteaccess/remoteaccess_test.go` | 未查清；T6（跨领域按上表） |
| `internal/ruleset/auth.go` | 未查清；T6（跨领域按上表） |
| `internal/ruleset/auth_test.go` | 未查清；T6（跨领域按上表） |
| `internal/ruleset/exclude.go` | 未查清；T6（跨领域按上表） |
| `internal/ruleset/fetch.go` | 未查清；T6（跨领域按上表） |
| `internal/ruleset/parse.go` | 未查清；T6（跨领域按上表） |
| `internal/ruleset/ruleset_test.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/client.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/journal.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/journal_test.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/main.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/mark_linux.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/mark_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/mark_other.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/neigh.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/parser.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/parser_test.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/peercred_linux.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/peercred_other.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/relay_test.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/resolver.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/resolver_test.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/selfcheck.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/selfcheck_test.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/server.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/server_test.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/status.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/status_linux_test.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/status_test.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/targetstats.go` | 未查清；T6（跨领域按上表） |
| `internal/sniff/verify_fixture.go` | 未查清；T6（跨领域按上表） |
| `internal/sshexec/banner.go` | 未查清；T3 |
| `internal/sshexec/channel.go` | 未查清；T3 |
| `internal/sshexec/channel_test.go` | 未查清；T3 |
| `internal/sshexec/pool.go` | 未查清；T3 |
| `internal/sshexec/pool_test.go` | 未查清；T3 |
| `internal/sshexec/sshexec.go` | 未查清；T3 |
| `internal/sshexec/sshexec_test.go` | 未查清；T3 |
| `internal/sshexec/sshtest/sshtest.go` | 未查清；T3 |
| `internal/store/store.go` | 未查清；T6（跨领域按上表） |
| `internal/store/store_test.go` | 未查清；T6（跨领域按上表） |
| `internal/unlock/policy_test.go` | 未查清；T5 |
| `internal/unlock/report.go` | 未查清；T5 |
| `internal/unlock/report_test.go` | 未查清；T5 |
| `internal/unlock/unlock.go` | 未查清；T5 |
| `internal/unlock/unlock_test.go` | 未查清；T5 |
| `internal/validate/allocations.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/endpoint_access.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/group_resolver.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/hubs.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/mesh.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/mesh_test.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/nested.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/nested_test.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/noix.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/noix_test.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/ordered.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/ports.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/reachability.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/relaybackup_test.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/remote_access.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/sharing.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/sniff.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/validate.go` | 未查清；T6（跨领域按上表） |
| `internal/validate/validate_test.go` | 未查清；T6（跨领域按上表） |
| `internal/verify/verify.go` | 未查清；T6（跨领域按上表） |
| `internal/verify/verify_test.go` | 未查清；T6（跨领域按上表） |
| `internal/wsstest/wsstest.go` | 未查清；T6（跨领域按上表） |
| `web/README.md` | 未查清；T6（跨领域按上表） |
| `web/chunks.ts` | 未查清；T6（跨领域按上表） |
| `web/demo.html` | 未查清；T6（跨领域按上表） |
| `web/index.html` | 未查清；T6（跨领域按上表） |
| `web/package-lock.json` | 未查清；T6（跨领域按上表） |
| `web/package.json` | 未查清；T6（跨领域按上表） |
| `web/public/favicon.svg` | 未查清；T6（跨领域按上表） |
| `web/src/App.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/CloudflarePage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/ConnectionLogsPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/CredentialsPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/DNSLogsPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/DNSView.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/DeployPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/DeployVerifyGroup.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/DeploymentGuide.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/ErrorBoundary.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/ExitsPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/HelpGuide.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/LinkLogsPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/ListsPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/MeshDeploy.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/MeshLegQuality.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/OverviewPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/PanelUpdate.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/Preflight.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/RelaySharing.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/RemotePage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/RulesImport.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/RulesPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/ServersPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/Sniff.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/TopologyPage.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/TrafficChart.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/TunnelCandidates.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/UnlockPage.tsx` | 局部证据，余项未查清；T5 |
| `web/src/WSS.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/Withdraw.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/api.ts` | 未查清；T6（跨领域按上表） |
| `web/src/channels.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/channels_candidates.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/demo/api.ts` | 未查清；T6（跨领域按上表） |
| `web/src/demo/chrome.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/demo/demo.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/demo/demo_pages_degraded.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/demo/demo_pages_healthy.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/demo/demo_pages_states.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/demo/demo_pages_unavailable.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/demo/demo_phone.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/demo/fixtures.ts` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/degraded.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/deploy-compensated.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/deploy-done.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/deploy-rate-limited.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/deploy-running.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/deploy-skipped.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/deploy-unknown.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/deploy-verify.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/healthy.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/logs-empty.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/logs-off.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/preflight-blocked.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/save-refused.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/generated/unavailable.json` | 未查清；T6（跨领域按上表） |
| `web/src/demo/main.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/demo/scenarios.ts` | 未查清；T6（跨领域按上表） |
| `web/src/demo/testkit.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/deploy_crash.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/deployment_guide.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/deployment_guide_verify.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/dns_view.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/help_guide.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/host_mesh.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/host_mesh.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/keyword_note.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/layout_b.css` | 未查清；T6（跨领域按上表） |
| `web/src/layout_c.css` | 未查清；T6（跨领域按上表） |
| `web/src/layout_fixtures.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/layout_pages.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/lazy_routes.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/leak_status.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/log_common.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/log_pages.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/log_routes.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/main.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/nav_routes.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/node_blockers.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/overview_traffic.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/pages_deploy.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/pages_exits.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/pages_fixtures.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/pages_remote_unlock.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/pages_rules_topology.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/panel.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/panel_update.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/prose_budget.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/prose_check.ts` | 未查清；T6（跨领域按上表） |
| `web/src/region_refs.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/rules_apply_line.test.tsx` | 未查清；T4（安装安全边界 T3） |
| `web/src/rules_ordered.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/second_pass.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/sniff_journal.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/sniff_paths.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/socks_version.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/state.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/status_words.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/styles.css` | 未查清；T6（跨领域按上表） |
| `web/src/table_budget.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/test-setup.ts` | 未查清；T6（跨领域按上表） |
| `web/src/testing.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/theme.test.ts` | 未查清；T6（跨领域按上表） |
| `web/src/theme.ts` | 未查清；T6（跨领域按上表） |
| `web/src/topology_contract.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/topology_no_ix.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/types.ts` | 未查清；T6（跨领域按上表） |
| `web/src/ui.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/ui_base.tsx` | 局部证据，余项未查清；T4（安装安全边界 T3） |
| `web/src/ui_layout.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/unlock_manual.test.tsx` | 未查清；T6（跨领域按上表） |
| `web/src/vite-env.d.ts` | 未查清；T6（跨领域按上表） |
| `web/tools/ui-audit.js` | 未查清；T6（跨领域按上表） |
| `web/tsconfig.json` | 未查清；T6（跨领域按上表） |
| `web/vite.config.ts` | 未查清；T6（跨领域按上表） |
| `web/vite.demo.config.ts` | 未查清；T6（跨领域按上表） |

新增文件：本记录、`internal/compile/review_topology_test.go`、`internal/compile/testdata/review_topology.json`、`docs/evidence/review-391aa50/baseline.sha256`、`docs/evidence/review-391aa50/baseline-bundles.json`。另向 `docs/verification.md` 追加本轮证据边界。

本次接续仅核对证据内部一致性：267 份 base64 解码内容与各自摘要一致，清单覆盖 HEAD 的 687 个跟踪文件，baseline.sha256 七条摘要与文件一致。此项不构成运行时验证；未执行配置的全量检查，留给 Concord 与独立 QA。

离线执行记录：`GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOCACHE=/private/tmp/meridian-review-t1-gocache go test ./internal/compile -run ^TestReviewTopologyBaseline$ -count=1` 返回 0。仅用于核对冻结比较入口可执行，不替代 Concord 配置检查或独立 QA，不证明数据面安全。

## T2 接续编码记录：未完成，不可作为交付或部署依据

本次仅修改 `share_table_route`、`share_tables`、`share_designate`、`share_apply` 的路由错误传播。每条 IPv4/IPv6 `route replace` 显式失败返回 3，嵌套调用立即传播；不依赖 Bash 的 `set -e`，因为调用处处于条件表达式时 Bash 会禁用函数体中的 errexit。成功路径的路由、权重和命令顺序不变。

新增 `TestShareRouteFailurePropagation`：合成 Bash 函数逐条注入 table（4）、designate（8）、tables（12，含备用表）、apply（16）失败，共 40 个位置，后续桩命令原本会成功；断言调用不成功且失败后不再执行后续路由。改动前复现早期失败被覆盖，改动后该定向命令返回 0。此记录仅为编码反馈，不是 Concord 检查或独立 QA 的结论。

**阻断交付的未完成内容**：尚未实现受保护的数据面事务、完整上一成功快照、补偿及补偿失败持久阻塞、并发/代次控制、有限重试、应用后状态发布协议；`RunStep` 与分组/非分组 fallback 的提前发布仍存在。当前 nft 先于路由更新，路由失败仍可能留下部分数据面，不得把此次错误传播修改当作安全切换修复。尚未完成上述故障矩阵、NAT 主中继故障/经中继备用/管理回程/Mesh 不变量证据。

未更新原始编译基线或任何 golden。当前必要脚本文本变化会使冻结基线及涉及共享脚本的摘要比较失败；须在完整 T2 实现后逐段说明并单独记录允许的差异，不能直接重写 T1 原始证据来掩盖它们。现有网关未部署，因此没有实际网关行为变化；若仅安装此局部版本，路由操作失败会更早返回非零，但不能保证恢复或面板状态正确。

### T2 再次接续记录（仍未完成）

接续时工作区已有 `share_txn.go` 的保护/快照/补偿框架、安装路径锁定和 `RunStep --candidate` 改动；以上上一段关于“尚未实现”的描述是此前进度，不能作为当前文件内容说明。框架存在不等于完成契约。

本次修正该框架中的管理保护缺陷：`meridian_switch` 的 forward 基础链原为 `policy drop`，四条 SSH 例外使用 `return`。基础链中的 return 执行链策略，因此这些例外仍然丢包。复现条件是安装或切换已加载临时保护，SSH 转发命中任一例外。改为 `policy accept` 并在四条例外之后追加 `counter drop`；管理流量继续经过其他既有基础链，其余流量在此丢弃。未添加任何路由或直连例外。新增 `share_txn_test.go` 固定此规则结构；这不是 Linux 数据面验证。

尚未完成的 T2 交付要求：完整事务故障矩阵（并发、发布失败、中断、补偿失败与重试）、控制器重启后 fallback 承载/时间同步、NAT 主中继故障后经已有备用路径的管理回程及 Mesh 不变量、必要 golden 与冻结基线差异的逐项记录。当前控制器初始化仍将 `fb_up` 设为 main、`fb_switched` 设为 0，不能据此声称重启保持上一成功承载时间。原始基线和 golden 均保持原样。未部署，实际网关行为没有变化。此记录仅为未完成编码交接，不是验证、批准或任务完成标记。

## T2 完成记录（修订 5 接续写手）

本节取代上方两段“未完成”记录对当前代码的描述（那两段保留为过程历史）。以下为编码与合成桩证据，不是 Linux 数据面验证、独立 QA 或部署批准；未连接任何远程主机，未部署。

### 实现（对应切换契约 1–7）

- **逐命令错误传播**（契约 2）：`share_table_route`/`share_tables`/`share_designate`/`share_apply_raw` 每条 IPv4/IPv6 `route replace` 失败即返回 3；参数校验通过后的任何失败在事务内映射为 3，不再回落到“拒绝即改用 fallback”。
- **受保护事务** `share_apply`（`internal/compile/share_txn.go`）：切换锁（flock，安装/控制器/直接调用同一把锁）→ 先校验再动数据面 → 写 `pending` → 独立 `inet meridian_switch` 保护表 → nft 批 + 全部路由 → 发布候选 status/state → 记录版本与参数为成功快照 → 撤保护 → 切 `current` 代次 → 写 `SH_APPLIED`、清 `pending/blocked/failed`。
- **补偿**（契约 3–4）：失败时保持保护，仅重放 `current` 指向的上一成功快照（版本须等于当前 `SH_VERSION`），成功后恢复上一成功 status/state，再撤保护；状态 `degraded`+`apply_failed`，路径、`since`、`switched` 均为上一成功值。
- **有限重试**（契约 6）：补偿成功后写 `failed`（次数、下一次允许时间；退避 30 s、60 s），期间 `share_step` 返回 5，不触碰数据面；累计 3 次后保持在上一成功路径，只有完整安装可解除。一次尝试最多一次补偿。
- **恢复阻塞**（契约 5）：无可信快照、补偿失败、状态发布失败、残留 `pending`（进程被杀）、配置版本变化：保留保护表、删除成功标记、`blocked` 持久（/run 下，跨控制器重启），状态 `down`+`recovery_blocked`/`config_changed`，最后成功记录仅作历史。仅 `SH_INSTALL=1`（meridian-up/routes 完整安装）可清除。
- **决策与已应用分离**（契约 1）：`path-step` 必须给 `--candidate`，只把 state/status 写入候选目录，不写正式 state/status；shell 在应用成功后发布。Go 无 state 时（fallback 之后）由 `stateFromAppliedStatus` 从已应用记录恢复承载、指定中继、`since`、`LastSwitch`。fallback（分组/非分组）在候选里生成记录，失败时 `fb_*`/`SH_R_*` 恢复为调用前值；成功后从 `current` 快照装载 `fb_*`（`share_load_applied`，替代原 `share_group_sync` 及“决策即写 fb_up”）。重启后的 fallback 承载与切换时间来自最后成功快照。
- **相同决策捷径**：与 `SH_APPLIED` 相同且无 hold/block 时不再加保护、不改内核，只把新 status 发布到当前快照；每 12 次完整重放一次（受保护事务）以自愈。代价：自愈那一次有毫秒级转发保护窗口。
- **SSH 管理例外**（核实并修补）：forward 链 `policy accept`+例外 `return`+`counter drop`（上一写手已修 drop policy 使 return 失效的问题）；本次补 output 链 `ip/ip6 daddr 10.66/fd66 tcp sport 22 return`——原先网关自身 sshd 经隧道回给管理端的应答会被 `ip daddr 10.66.0.0/16 drop` 丢弃。局域网侧 SSH 走 input，不受保护表影响。
- 面板告警文案：`apply_failed`、`recovery_blocked`、`config_changed`、`install_failed`、`guard_failed`（`internal/api/sharing.go`）。

### 故障注入回归（合成 bash 桩，非 Linux 数据面）

`internal/compile/share_txn_fault_test.go`，分组（relay backup 示例）与非分组（shared_relays）两种拓扑，每次 bash 为新进程（等同控制器重启）：

- `TestShareTxnRouteFailureCompensates`：切换（主→备）时第 1–20 条 IPv4/IPv6 路由命令逐条失败：rc 3、目标未发布、标记仍为上一成功、无保护残留、快照重放；退避内重启也不重试；退避后一次重试成功且 `switched` 为实际应用时间。
- `TestShareTxnCompensationFailureBlocks`：补偿也失败 → 保护保留、`blocked`、`down`；重启且内核恢复后仍阻塞且无新批；完整安装解除。
- `TestShareTxnNftRefusal`：nft 批拒绝 → 补偿；补偿批也被拒 → 阻塞。
- `TestShareTxnRetryBudget`、`TestShareTxnFirstApplyFailureAndCrash`（无快照首次失败；残留 pending）、`TestShareTxnStatusPublishFailure`、`TestShareTxnFallbackFailureKeepsCarrying`（fallback 切换失败不推进 `fb_up/fb_switched`/记录）、`TestShareTxnSerialised`（锁串行化）。
- `internal/pathquality/run_test.go`：无候选目录拒绝且不写 state/status；从已应用记录恢复状态。
- 既有 `TestRelayBackupControllerSync`/`TestRelayBackupShell`：控制器桩改为按上一记录计算 `since/switched` 并输出 relay 行（真实 `path-step` 的行为），直接调用改用 `share_apply_raw`（校验与单批语义），预期值未改。

### Golden 与冻结基线变更（均因上述必要脚本变化）

只有网关的 `meridian-routes.sh`、`meridian-up.sh`、`meridian-failover.sh` 变化，其余文件字节不变：

- `testdata/relay_backup_example.golden`：上述三个文件摘要。
- `golden_single_hub_test.go` `preLogCompile["shared_relays"]`、`mesh_transport_test.go` `noMeshCompile["shared_relays"]`：同三脚本，注释已标注。
- T1 冻结基线 `baseline-bundles.json` 原样保留。`TestReviewTopologyBaseline` 新增逐文件接受清单 `docs/evidence/review-391aa50/t2-accepted.json`：每项须替换一个 T1 原摘要（from）、匹配新摘要（to）并带原因；清单外任何文件、顺序或输入变化仍失败。

### 剩余（交 T6 或人工）

隔离 Linux netns 数据面证据（保护表实际放行管理 SSH、补偿期间无直连/IPv6 绕过）、NAT 主中继故障后经备用路径的管理回程与 Mesh 不变量未在本任务中动态验证；`pathquality` 其余文件（measure/qos/speedtest/mesh 等）仅就 RunStep 发布路径审过，未逐项审计。

## T3–T6 完成记录（修订 5，Claude 写手）

以下为编码与合成回归证据（假宿主、bash 桩、jsdom），不是 Linux 数据面验证、独立 QA 或部署批准；未连接远程主机，未部署，未提交。T1 基线与 T2 改动全部保留。

### T3 自动安装、事务恢复与宿主执行边界

审查结论（逐项，均附现有或新增回归）：

| 不变量 | 结论 | 证据 |
| --- | --- | --- |
| 规则/解锁白名单：预期外文件、增删、其他节点、越界地区组拒绝 | 现有实现满足 | `compile.RuleChange`；`TestRuleChangeRefusesOutside`、`TestUnlockAutoApplyRefusesExtras`、`TestUnlockManualGroupMoveNeedsHub` |
| 保存与安装竞争不用过期快照、不覆盖新版本 | 满足（失败关闭）；锁内重新核对已安装版本、去规则部分后的同步与 canonical 固定 | `TestRuleAutoApplyConcurrentChangeRefused`、`TestRuleAutoApplyVersionMovedMeanwhile`、`TestRuleAutoBusy*`；`applyGateway` 的 `codeAutoChanged` |
| 合并期间两个“空闲”保存交错（都通过空闲检查） | 不是缺陷：后到者的范围不并入 base 时，白名单/onlyTargetsDiffer/同步检查拒绝，即失败关闭（多一次手动安装），不会多装 | 静态追踪 `rulesAutoAfterSave` |
| 事务每个阶段崩溃后重启恢复 | 满足；新增全阶段注入 | 新 `TestCrashAtEveryHostStepRecovers`：从一次成功运行收集全部宿主步骤标签（预检、fwd-remove、fwd-activate），新增/删除两个方向，各在正向与补偿（comp-*）中崩溃；新进程 Recover 后无日志、版本与宿主一致、二次 Recover 空操作、日志未清时新安装 `ErrPending`、恢复后可再安装。prepared/commit 阶段由既有 `TestRestartAfterHostConvergedFinishesCommit`、`TestRestartMidRollbackRecovers` 覆盖；补偿失败不报成功由 `TestCompensationFailureIsNotSuccess` 覆盖 |
| 宿主固定动作：参数数组、无 shell、名称白名单、路径 | 满足：`ExecRunner` 仅 `exec.CommandContext(绝对路径, args...)`，固定环境；单元/接口/表名正则；预检路径 `ValidPath`（绝对、已清理、无 `..`、字符白名单、固定前缀） | `TestValidateRejectsAnythingButManagedNames`（`; rm -rf /`、`$(id)`、`../`）、`TestAgentRejectsUnknownFieldsAndBadToken`、`TestValidatePaths`、`TestTokenFileCreatedPrivate` |
| 凭据脱敏（正常/错误/恢复日志） | 满足：事务错误经 `redactErr`，已安装副本去 PrivateKey | `secrets_seams_test.go`、`TestRuleAutoApplyRuleSet`（规则集凭据不入记录） |
| 预检针对实际安装的同一 bundle | 满足：规则/解锁自动安装对 `next.Files` 预检，再以 `next.Canonical()` 固定安装；拓扑或决定变化 409 不安装 | `TestRuleAutoApplyPreflightWarning`、`TestUnlockAutoApplyPreflightWarning` |
| 远程接入快速生效不跑宿主预检 | 不是缺陷（设计）：仅当差异只有 mra.conf 的 [Peer] 段且 [Interface] 不变时走 peer sync，不改端口/单元/监听，预检所查内容不受影响 | `remote_fast.go` 头注释、`TestRemoteFastApplyNotEligible` |

T3 未改生产代码（未发现确认缺陷）；新增文件内测试见上。

### T4 自动安装重启恢复与轮询终态（缺陷已修）

- **缺陷 1（提案 P2，已确认）**：scheduled 记录持久化而执行者只在内存。复现：连续保存进入 scheduled，定时器触发前重启面板 → GET 返回 pending=false、last=scheduled，前端永远“将自动生效”。修复：`rulesAutoRecord` 记录写入进程 `boot`；读取时（`loadRulesLastLocked`，与 pending 判断同一把 `rulesAuto.mu`）若为 scheduled 且不属于本进程或本进程已无定时/运行，则**持久化**改写为 `required` + `interrupted: true` + “面板重启，合并的自动生效没有执行，需要到部署页安装”。从不恢复执行；新保存从头校验。无 boot 字段的旧记录同样视为中断。
- **缺陷 2（新发现，竞争）**：`rulesAutoAfterSave` 在释放 `rulesAuto.mu` 后才写 scheduled；定时器极短时，合并运行可能先写结果，随后被这条 scheduled 覆盖，留下无执行者的 scheduled。另：合并运行结束时若已有更新的保存排队，旧结果会覆盖新 scheduled。修复：scheduled 在锁内写；运行结果仅在没有更新排队（`timer == nil`）时写入（`recordRulesOutcome`/`rulesAutoFire`）。
- 前端 `RulesApplyLine`：轮询 60 次耗尽显示“结果待确认 · 重新查看 · 去部署”，不再停在“将自动生效”；每次请求后检查取消信号，旧保存的晚到响应不覆盖新保存结果；卸载取消。
- 回归：`TestRuleAutoApplyScheduledLostOnRestart`（scheduled → 重启 → 两次读取均为中断且已持久化 → 再次重启不变 → 未安装 → 新保存独立求值）、`TestRuleAutoApplyLegacyScheduledRecord`；`rules_apply_line.test.tsx` 新增耗尽/重新查看、卸载晚到响应、新保存替换旧轮询三例。
- 测试稳定性：`TestRuleAutoApplyCoalesces`、`TestRuleAutoApplyVersionMovedMeanwhile` 的合并窗口由 400 ms 放宽到 3 s——在 `-race` 下单次保存超过 400 ms，第二次保存落在窗口外（时间依赖，非产品缺陷）。

### T5 解锁异步状态与推荐→路由一致性

- **缺陷（提案 P2，已确认并修复）**：`UnlockPage` 用异步 `setInterval`，请求可重叠，晚到的旧 running 响应覆盖完成状态并重启轮询，卸载后仍回写。修复：首次读取、轮询、停止/采用/409 后的刷新共享一个读取代次（`gen`），只采用最新读取的结果；轮询改为“响应后再调度”的 `setTimeout`，`AbortSignal` 贯穿 `api.getUnlockMatrix(signal)`；启动新探测时作废之前的读取。
- 回归 `web/src/unlock_polling.test.tsx`（可控 Promise + 假定时器）：慢于间隔的请求不重叠；失败后继续、完成后停止；停止后的新结果先到、旧 running 后到被丢弃且不重启轮询；卸载取消且无后续请求；完成后再次探测重新轮询。
- 推荐→路由：新 `TestUnlockRecommendationReachesRoute` 串联矩阵推荐 → 预览 → 确认 → 存储的规则目标 = 推荐地区组 → 矩阵“当前”出口 = 推荐出口且推荐标记已采用 → 安装后网关规则行指向该出口；激活失败时 `fast_apply` 不为 applied、`apply_required=true`、版本不变。`TestUnlockConfirmStaleRecommendationRefused`：探测结果过期后确认 409 且不写入。身份变化、地区组共享规则的影响确认由既有 `unlock_identity*_test.go`、`TestAdoptImpactCountsOtherGroupRules`、`TestUnlockManualRefusals` 覆盖。未发现推荐与实际写入目标的偏差。

### T6 其余审查项与兼容交付

- **缺陷（新发现，已修复）**：`ListsPage` 名单更新任务轮询同为异步 `setInterval`，慢响应时请求重叠，晚到的 running 响应可覆盖已完成任务并重启轮询，卸载后仍回写。复现：`GET /api/lists/job` 超过 2 s。修复同 T5（响应后调度 + AbortSignal，`api.getListsJob(signal)`）。回归 `web/src/lists_polling.test.tsx`。
- 测试数据竞争（测试缺陷，非产品）：`TestKeywordNoteInImportPreview` 在后台预取仍读取 `fakeFetch.body` 时无锁写入，`go test -race ./internal/api` 失败；改为持 `f.mu` 写入。
- 其他前端轮询逐个核对：`DeploymentGuide`、`MeshDeploy`、`RulesImport` 规则集刷新经 `useApi`/顺序 `load`，有代次或幂等，不是缺陷；`PanelUpdate` 已有 abort + busy 保护；`TrafficChart` 时钟为纯本地定时器且卸载清除。
- 日志增长：DNS 日志（`dnsjournal`：记录数、时间、总字节三重预算，原始审计文件与轮转副本共享预算）、连接日志与嗅探日志均有上限与轮转；本轮未发现无界增长。
- 编译兼容：T3–T6 未改编译器或运行时脚本；全部产物仍等于 T1 原始字节，只有 T2 已登记的 `t2-accepted.json` 差异（网关三个脚本）。未新增 accept 文件；`TestReviewTopologyBaseline` 与五份 golden 通过。
- **未验证（平台限制）**：本机为 macOS（Darwin），无 Linux 网络命名空间，未运行任何隔离数据面验证。以下结论**仍未验证**，不得据 bash 桩视为通过：T2 保护表对管理 SSH 的实际放行、补偿期间无直连/IPv6 绕过、NAT 主中继故障后经备用组的管理回程、Mesh 规则在切换后的保持、DNS 冷启动/切换时不回落。须在 Linux 隔离环境（`docs/verification.md` 已有 `docker run --privileged --network none` 方式）复验后才能作数据面结论。

### 网关可见行为变化（T3–T6）

无编译产物变化。面板：重启后遗留的“将自动生效”显示为“未自动生效：面板重启，合并的自动生效没有执行，需要到部署页安装”；轮询耗尽显示“结果待确认”；解锁与名单页的轮询不再重叠或被旧响应回退。

### 审查矩阵收尾

| 矩阵行 | 结论 |
| --- | --- |
| 编译字节与拓扑覆盖 | 关闭：仅 T2 登记差异 |
| 运行时主备/分担 | T2 关闭（控制流）；数据面见上方“未验证” |
| 自动安装白名单/并发 | 关闭（T3 满足 + T4 两处竞争已修） |
| 事务崩溃恢复 | 关闭（T3 全步骤注入） |
| 宿主固定动作/凭据/路径权限 | 关闭（现有实现满足，回归在案） |
| 经中继管理与无 IX 部署 | 未验证数据面 → 建议 R1 |
| 预检 | 关闭（同一 bundle 固定；远程快速生效设计上免预检） |
| DNS/IPv6/直连绕过 | 生成文本由既有 leak 测试与基线覆盖；隔离数据面未验证 → 建议 R1 |
| 解锁推荐→采用→路由 | 关闭（T5） |
| 自动安装前端终态 | 关闭（T4） |
| 其余前端关键页/日志导航 | 轮询类关闭（T5/T6）；其余页面未发现新确认缺陷，日志导航与恢复入口未改动 |
| 定时器/轮询/goroutine/日志增长 | 前端轮询关闭；日志预算已核对；后端 goroutine 未发现无界项 |
| 其余模型/规则/脚本/文档 | 本轮未逐文件深审 → 建议 R4 |

### 交给用户决定的建议（未实施）

| # | 问题 | 收益 | 代价 | 风险 |
| --- | --- | --- | --- | --- |
| R1 | 主备切换保护表、管理 SSH 例外、NAT 主中继故障后管理回程、Mesh 与 DNS/IPv6 不回落仅有 bash 桩证据 | 部署前得到真实数据面证据 | 在 Linux 主机用 netns/容器搭合成拓扑，约半天到一天 | 不做则首次真实故障才暴露；做时需特权容器 |
| R2 | Go 决策器与 shell fallback 各有状态机（T1 已列） | 消除发布时序类缺陷根源 | 控制器接口与迁移较大 | 旧二进制兼容 |
| R3 | 多节点安装无跨节点事务（T1 已列） | 部分安装边界清晰 | 需独立协议 | 管理通道中断时的可用性 |
| R4 | 全库逐文件深审未完成（模型、规则优先级、部署脚本、文档） | 发现剩余低频缺陷 | 再一轮审查 | 低 |
| R5 | 规则自动生效记录只保留最后一条，被中断的合并任务无历史 | 便于追查 | 增加小型环形日志 | 低 |
| R6 | 视觉与文案清理（T1 已列） | 更干净 | 逐页确认恢复入口 | 隐藏错误/日志入口 |

## QA 修复记录（Grok 只读 QA 建议 1–5）

- 失败的 fallback 切换不再推进计数：`share_fallback_step` 在失败时连同 `fb_in/fb_goods/fb_fails` 一并恢复。原先 `declare -p` + `eval` 去掉 `declare -a` 后对已有数组赋值成字符串（`fb_in='(...)'` 写进 `[0]`），数组实际从未正确恢复；改为逐个数组拷贝（兼容 bash 3.2 测试桩与 Linux bash 5）。回归：`TestShareTxnFallbackFailureKeepsCarrying` 现在断言失败前主组中继已连续失败 2 次、备组两中继在组内，第 3 次（FAILS_NEED）是真实的主→备组切换并注入失败，失败后 `fb_*`/`SH_R_STATUS`/`SH_R_W` 与切换前完全一致，记录仍为 main、switched 0。
- 遗留 `pending` 不再一律围栏到完整安装：`pending` 现记录 `版本 目标快照`。重启时若 `current` 已指向该目标（提交点：只在内核切换、发布、撤围栏全部成功后写入）、快照版本等于本编译版本且 args/status 齐全，则在围栏下按快照重放一遍 `share_apply_raw` 作为内核状态校验（切换自身的命令），成功后撤围栏、写成功标记、删 `pending`；任何一项无法证明（版本不符、目标不是 current、缺 args、重放失败）仍围栏并 blocked。回归（分组/不分组各一）：`TestShareTxnKilledAfterCommitRecovers`（SIGKILL 于写成功标记前、删 pending 前）、`TestShareTxnKilledBeforeCommitBlocks`（ip 第 1/5/最后一次调用时 SIGKILL）、`TestShareTxnPendingMismatchBlocks`（pending 版本、快照版本、缺 args、重放失败）。
- 网关脚本因此变化：`relay_backup_example.golden`、`shared_relays` 的 pre-log 与 no-mesh 摘要已更新；`docs/evidence/review-391aa50/t2-accepted.json` 中网关三个脚本的 `to_sha256` 更新并在 reason 中追加本次原因（from 仍为 T1 原摘要）。
- 前端：解锁页轮询在本次答复被更新的读取取代时丢弃答复但继续轮询（探测仍在运行时）；新增回归“停止后的刷新仍报告运行中”。名单页新增乱序回归：任务完成后迟到的“运行中”快照（策略保存的答复）被丢弃且不重新开始轮询。

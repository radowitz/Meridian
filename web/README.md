# Meridian 控制面板（web/）

React 18 + Vite + TypeScript + antd 5。界面文字全部中文，用语跟 `docs/` 一致。

```sh
npm ci
npm run dev      # 开发服务器，/api 代理到 127.0.0.1:8787（make run）
npm run build    # tsc --noEmit && vite build → dist/
npm test         # vitest + Testing Library + jsdom，对着内存里的假 API
npm run demo:build && npm run demo:serve   # 演示预览（合成数据，见下面「演示预览」）→ dist-demo/
```

## 面板约定

### 外壳与路由（`App.tsx`、`state.tsx`）

- 侧栏分组：概览 `#/` · 网络（拓扑 `#/topology`、出口 `#/exits`、分流规则 `#/rules`、名单 `#/lists`）· 解析与日志（解析设置 `#/dns`、解析日志 `#/dns-log`、连接日志 `#/conn-log`、链路日志 `#/link-log`）· 资源（服务器 `#/servers`、密钥 `#/keys`、Cloudflare `#/cloudflare`）· 接入（远程接入 `#/remote`）· 运维（部署 `#/deploy`、解锁 `#/unlock`、防泄露 `#/leak`、验收 `#/acceptance`）。路由表是 `App.tsx` 里的 `NAV`：每条路由有自己的 `load: () => import("./XxxPage")`，页面按路由懒加载（`lazyPage`），在 `PageSlot` 里渲染：下载中显示加载骨架（`role="status"`「页面加载中」），页面文件下载失败（断网，或面板升级后旧标签页要的文件已经不在）显示「面板已更新，请刷新」和「刷新」按钮（不自动刷新），页面渲染时抛错仍是「这个页面出错了」和「重试」。拆包规则见下面「首屏与拆包」。窄于 `lg` 时侧栏变成抽屉。
- 哈希路由，自己实现，没有路由库：`useRouter()` 给出 `route.page`、`route.params`（`#/servers/srv-1` → `["srv-1"]`）、`route.query`，`navigate(href("servers", id))` 跳转。对象链接一律 `href(page, id)`：节点 `#/topology/<node>`、服务器 `#/servers/<id>`、密钥 `#/keys/<id>`、地区组 `#/exits/<id>`、规则 `#/rules/<id>`、设备 `#/remote/<id>`、Mesh 部署 `#/cloudflare?section=mesh`。页面用 `route.params[0]` 打开对应对象的详情抽屉。
- 顶栏：宿主执行通道是否可用、数据面安装版本或「数据面未安装」、未完成的安装事务、进行中的任务（名单更新、解锁探测、Mesh 部署/撤回），以及常驻的「有改动尚未安装 / 已应用，尚未安装 / 尚未安装到网关 / 拓扑无法编译」。这些都来自一个只读接口 `GET /api/status`（`useStatus()`：`status`、`install`、`jobs`；平时 20 秒、有任务运行时 5 秒轮询一次）。它和**已安装清单**比较，不是和上一次「应用」的快照比较，所以「应用但没安装」也会显示待安装。**只改文档的修改（API 返回 `apply_required: true`）之后调用 `useStatus().markApplyRequired()`**，顶栏立即显示待安装。
- 拓扑文档：`useTopologyDoc()` 持有整份拓扑的工作副本（`topo`、`setTopo`、`dirty`、`save(draft)`、`validate()`、`reload()`、`issues`、`paths`）。编辑整份文档的页面放 `<TopologyDocBar/>`（校验 / 放弃 / 保存草稿 / 保存，并自动注册离开提示）。**用其他 API 改了存储里的文档（名单策略、地区组、远程接入……）之后调用 `applyServerChange(t => …)`，把同样的改动应用到工作副本**，否则之后整份保存会把旧值写回去。
- 离开提示：`useUnsavedGuard(dirty, message?)`，覆盖站内跳转、浏览器前进后退和关闭标签页。

### 共享组件（`ui.tsx`）

页面一律从 `./ui` 导入。外壳和登录页要用的部分（`StatusTag`、`ERROR_TEXT` / `errorTitle` / `ApiErrorAlert`、SSH 限速冷却、`Link` / `RefList`、`Mono` / `CommandBlock` / `EllipsisText` / `CopyButton`、`PendingInstallIndicator` / `ApplyRequiredNotice`）放在 `ui_base.tsx`，由 `ui.tsx` 原样再导出；`App.tsx` 只导入 `ui_base.tsx`，这样表格、对话框、分页这些页面共用的代码不进入口块。概览要显示的、属于别的页面的状态词（服务器就绪、地区组实际状态、承载枢纽、Mesh 部署记录与权限检查摘要）在 `status_words.tsx`，概览不必为了一个标签加载出口、服务器、密钥和 Mesh 页面。

| 组件 / 函数 | 用法 |
| --- | --- |
| `Page` / `PageHeader` | 每个页面的骨架：标题、一句话用途、右侧主操作 `extra`，然后内容 |
| `Section` | 页面里带标题的白底分块 |
| `StatusTag kind=…` | 全面板唯一的状态词表和颜色：`ok` 正常/已完成、`attention` 需要处理、`failed` 失败、`pending` 配置完成但尚未安装、`unverified` 未验证、`signoff` 待人工签收、`running` 进行中、`neutral` 未配置。子元素可以改文字，不能改颜色。配置了或连得上的东西绝不能用 `ok` |
| `useApi(loader, deps)` | `{data, error, loading, reload, setData}`；`reload` 保留旧数据 |
| `DataView state isEmpty empty` | 统一的加载骨架 / 错误（API 原文 + 重试）/ 空状态 / 数据 |
| `EmptyState title description action` | 空状态：这是什么 + 主操作 |
| `useAction()` | 变更：`run(fn, key?, onError?)`，`busy` 用来禁用按钮（`busy === key`），`error` 交给 `ApiErrorAlert` |
| `ApiErrorAlert error onRetry` | API 错误：`code` 的中文（`ERROR_TEXT`，所有错误码的中文只在这里维护）+ 服务端原文 + `in_use_by` 引用者链接 |
| `RefusedDialog error` | 删除或修改被 409 `in_use` / `account_locked` 拒绝时，弹窗列出引用者链接 |
| `RefList refs` / `refLink(ref)` | `in_use_by` 引用者列表（按 `kind` 生成链接） |
| `showFieldError(form, err, fields)` | 把带 `field` 的 API 错误放到表单字段上 |
| `SecretField` | 只写的秘密输入（见下） |
| `useConfirmDanger()` | 危险操作确认：`confirm({title, consequence, okText, onOk})`，`consequence` 用一句话说后果 |
| `Mono copy block ellipsis` / `CopyButton` | ID、地址、指纹、公钥用等宽字体，可复制 |
| `TimeText value` | 相对时间，悬停显示绝对时间；空值和零时间显示「—」 |
| `Facts items` | 详情抽屉里的键值行 |
| `Tile` | 概览卡片 |
| `PendingInstallIndicator` / `ApplyRequiredNotice` | 顶栏的待安装标记；页面内「已保存但还没安装」的提示 |
| `TopologyDocBar` / `IssueList` | 整份拓扑的保存条和校验问题 |
| `TABLE_SCROLL` / `RowActions` | 每个表格都用 `scroll={TABLE_SCROLL}`（`x: "max-content"`：放不下时在表格自己的框里横向滚动，页面不横向滚动）；名称列 `className: "cell-name"`（不换行，中文不会一字一行），长文字列给 `width` 和 `className: "cell-text"`，操作列 `title: "操作"`、`fixed: "right"`、`className: "cell-actions"`。操作多于两个时用 `RowActions`：常用的一个留成按钮，其余放进「…」菜单（`aria-label` 为「<名称> 的更多操作」）。在 900 px 和 600 px 下看过 |
| `downloadText(filename, text)` | 浏览器本地生成文件下载（Blob，不经网络、不进存储），远程接入的一次性配置用它 |
| `Link to` | 站内链接（走路由和离开提示） |

新建 / 编辑在 `Drawer` 里用表单，不用长弹窗；多阶段流程用 `Steps`，当前阶段的结果直接显示在步骤下面（参考 `ServersPage` 的接入流程、`MeshDeploy` 的阶段）。

### 秘密

- 密码、私钥、私钥口令、API token、远程设备的一次性配置：从不从服务端读回（API 也不返回），不放进 `localStorage` / `sessionStorage` / IndexedDB / URL，不写控制台。
- 表单里用 `SecretField`：不预填、`autocomplete` 关闭；服务端说已设置时显示「已设置 · 替换」。**请求结束后（成功或失败）立即清空这些字段**：`form.setFieldsValue({password: undefined, …})`，抽屉用 `destroyOnClose`。
- 远程接入的配置（`createRemoteDevice` / `regenerateRemoteDevice` 返回的 `config.text`）只放组件 state；二维码用 antd `QRCode` 在浏览器里生成；下载用 `downloadText`；离开后明确说明无法再次显示，只能重新生成。
- 面板口令：内存变量 + 镜像到 `sessionStorage`（`meridian.token`，只在本标签页、关闭即清除，刷新不用重输）；顶栏的锁按钮清除它。`localStorage` 里只有外观偏好 `meridian.theme`。
- 页面不发第三方请求：没有 CDN 字体或脚本、统计、远程二维码或头像服务；一切打包在内。API 字符串一律当文本渲染。

### API 客户端（`api.ts`、`types.ts`）

所有接口都有类型化的函数（服务器、SSH 凭据、Cloudflare、Mesh、名单、地区组、远程接入、解锁、防泄露、核心安装接口）。失败一律抛 `ApiError`：`status`、`code`、`field`、`inUseBy`、`issues`、`body`（Mesh 和名单的错误体里有额外字段，如 `not_ready`、`compensation_errors`、`job`）。字段名以 `internal/api/*.go` 为准。

### 测试（`testing.tsx`、`panel.test.tsx`、`test-setup.ts`）

- `fakeApi({"GET /api/servers": () => ({servers: […]}), "POST /api/servers/:id/test": (req) => reply(502, {…})})` 安装 fetch 假实现，`DEFAULTS` 让外壳安静；返回的对象有 `calls`（每个请求的 `method`、`path`、`params`、解析后的 `body` 和原始 `raw`）、`find("POST /api/x")`、`on(spec, handler)`。
- `renderAt("#/servers/srv-1")` 渲染整个应用；`webStorageDump()` 检查网页存储里没有秘密。
- antd 的两字按钮自动加空格已在 `ConfigProvider` 关掉（`button.autoInsertSpace=false`）；测试里的 `btn("删除")` 两种写法都能匹配。
- 测试文件参与 `tsc --noEmit`，但不在应用的依赖图里，不会打包。
- 页面交互测试按页面分在 `pages_exits` / `pages_deploy` / `pages_rules_topology` / `pages_remote_unlock.test.tsx` 四个文件里（共用 `pages_fixtures.tsx` 的帮助函数和合成数据），让 vitest 的多个 worker 并行跑；新用例放进对应页面的文件，不要让一个文件再长成整套的瓶颈。
- `test-setup.ts` 给 jsdom 的样式计算换了一个编译选择器缓存更大的 nwsapi 实例（原因见下面「前端测试耗时」）。不要为了快去掉 `findByRole` 的可访问名称或改用 `hidden: true`。
- `lazy_routes.test.tsx`：每条路由加载自己的页面模块；加载中状态；外壳里打开懒加载页面并从菜单跳到另一页；页面文件加载失败显示「面板已更新，请刷新」和「刷新」；页面渲染抛错仍是页面错误。

## 页面

| 路由 | 文件 | 内容 |
| --- | --- | --- |
| `#/` | `OverviewPage` | 状态和下一步（含「远端节点第一次下发」：还没有公钥的远端节点数，链到「部署 → 远端节点」）；地区组卡片显示总数，超过 6 个时有「还有 N 个 · 查看全部」 |
| `#/topology` | `TopologyPage` | 画布 + 右侧抽屉编辑节点/链路；删除节点时列出引用它的链路、地区组（变空组、失去手动指定时各有一句后果）、钉到它的规则（逐条选择改指向或删除，不选不能删）和关联的服务器，一步清理（`deleteNode`）；节点选择服务器（没有 `ssh_*` 输入）；「网关设置」抽屉（局域网、转运前缀、NAT64 预留……）；可点击的校验问题；`#/topology/<节点或链路>` 打开对应对象 |
| `#/exits` | `ExitsPage` | 按地区分区的地区组卡片：自动/手动、成员排序（拖动或上下箭头，一次 PATCH 保存整个顺序）、实际顺序和排除原因、手动指定和失败时行为、实际使用（只来自枢纽报告 `actual.state == "ok"`，其余显示未知和原因）与面板推算分两行、顶部「枢纽运行状态」条和读取按钮、默认组、删除被引用时列出引用者；不在任何组里的出口 |
| `#/rules` | `RulesPage` | 规则表按编译器的匹配顺序显示（`effectiveOrder`：手动规则总在内置规则前，再按优先级、ID）；上下移动和「…」里的移到最前 / 最后只在同一类里移动（`moveRule`：邻居之间有空位只改被移动的那条，否则把这一类按显示顺序以 10 为步长重编号，内置规则数值变了标「已改默认」）；去向是地区组或固定出口二选一；抽屉编辑并先调 `/api/validate` 把本规则的错误放到字段上；规则没有模式字段 |
| `#/lists` | `ListsPage` | 名单源和更新；末尾的「解析配置」区块只剩一句说明和到 `#/dns` 的链接（区块仍是 `id="dns"`，`#/lists/dns`、`#/lists?section=dns` 滚动到它；裸的 `#dns` 直接解析成 `#/dns` 页面） |
| `#/dns` | `DNSView`（默认导出 `DNSSettingsPage`，页面主体是 `DNSConfigView`） | 解析设置：顶部先说已保存的设置意味着什么（没有加密上游时：各出口向内置公共解析器明文查询，带「设置加密上游」按钮，点了展开全局表单并聚焦地址框）；出口解析上游（全局表单、按出口的表和编辑器、解析检查）；账户标识；解析路径；生成的 SmartDNS 配置；转发服务的逐解析器结果。表单里就地说明「地址自己填、账户标识单独保存并打码、证书主机名用 `{account}`」，示例只用虚构服务商。概览、网关设置的「解析（DNS）」、嗅探卡片都有到这里的链接 |
| `#/dns-log` | `DNSLogsPage` | 解析日志：开关与状态（先看能力门槛：不可用时只显示原因和处理办法，没有打开的入口；打开要勾选确认，保存后提示去部署页预检 → 确认 → 安装；关闭时说明安装成功后清除记录）；按设备汇总；查询记录（设备、时间、名字、结果、解析组筛选，游标分页）；清空；记录范围 |
| `#/conn-log` | `ConnectionLogsPage` | 连接日志：原来嗅探卡片里的设备连接日志整体搬来（设备列表、设备详情、筛选分页、正在转发、清空、异常停止提示、记录范围）；名字记录的开关仍在嗅探卡片（`#/rules?section=sniff`），这里说明并链接过去 |
| `#/link-log` | `LinkLogsPage` | 链路日志：当前状态（承载路径、异常对象及持续时间和依据、状态未知的对象、抖动中的对象）；事件时间线（对象、类别、时间筛选，游标分页，清空）；观测范围（依据强弱、不在记录范围内的内容）。采集空窗、「至少」的持续时间、空窗后才发现的变化、合并记录各按原样显示 |
| `#/servers` `#/keys` `#/cloudflare` | | 资源 |
| `#/remote` | `RemotePage` | 入口设置、路由器转发说明、设备表（运行状态或读不到的原因、配置过期）、一次性配置对话框（文本、复制、下载、浏览器本地生成的二维码、必须确认才能关闭、关闭即丢弃）、重新生成、停用、删除 |
| `#/deploy` | `DeployPage` | 待安装的改动（按节点、按文件的差分；「已应用但未安装」时改列 `/api/diff` 的 `installed`：安装会新增/修改/删除的网关文件，按哈希，没有逐行内容）、安装到本机（拒绝和失败一律按错误体的 `code` 解释，不匹配文字；`peer_keys_missing` 把每个对端链接到修它的地方）、「只写入数据目录」只在没有宿主执行通道时提供、回滚（`previous_available=false` 时不提供；已安装只提供含宿主网络，未安装只提供快照）、远端节点（推荐顺序、没有公钥的节点标「第一次下发」且主按钮是「生成密钥并下发」，`?section=remote` 滚到这里）、当前安装 |
| `#/unlock` | `UnlockPage` | 未验证声明、发起探测（服务、按组/出口、地址族、取消）、结果矩阵（服务 × 组/出口 × 地址族；「仅可达」与「解锁」颜色和文字都不同；只支持 IPv4 的服务在 IPv6 上是「不适用 · 仅 IPv4」，不算未知，旧记录里 `unknown` + `family_not_supported` 也这样显示）、每个服务当前所在出口、历史、平台目录 |
| `#/leak` | `LeakPage` | 四组检查；集成和人工两组无论接口返回什么都固定显示「未执行」/「待人工签收」；最后一列链接到对应的验收项并显示在那里记录的签收（文字，不改这一行的状态） |
| `#/acceptance`、`#/acceptance/<id>` | `AcceptancePage` | 验收目录：每项的影响与耗时、只读检查一键执行、演练先说明后果再二次确认（确认会过期）、人工项的步骤与签收；证据的各部分分开显示，过期的结果不计；宿主上未核验恢复的演练以页面唯一的提示显示，带重试与解除。其它页面用 `acceptance_hint.tsx` 的 `AcceptanceHint` 在「未验证」旁给出到条目的链接、状态和最近的有效结果（读 `GET /api/acceptance/summary`） |

三个日志页共用 `log_common.tsx`：开头两句话（`LogIntro`：记录什么、不记录什么、保留多久、存在哪里、谁能看）、明确的空状态（`LogEmpty`，`data-state` 区分未开启 / 未安装 / 没有运行 / 还没有数据）、范围说明的列表、解析日志与连接日志之间的跳转（`relatedHref` / `RelatedPanel`：链接只带设备地址、时间和 MAC——哈希片段，不发给服务端，也从不带名字；目标页向 related 接口查询有界时间窗，只有 `identity == "mac"` 才写「同一设备」，其余写明「未确认是同一台设备」及依据）。

测试：`panel.test.tsx`（资源页、名单、顶栏）和 `pages_*.test.tsx`（上面这些页面的关键交互，按页面分成四个文件）；`log_routes.test.tsx`（四个导航入口和路由、名单页的旧入口、各处到解析设置的链接）、`log_pages.test.tsx`（解析日志和链路日志）、`sniff_journal.test.tsx`（连接日志页和嗅探卡片的入口）、`dns_view.test.tsx`（解析设置）。

## 演示预览（只用于开发和验收）

用合成数据驱动**真实的外壳和页面**，在浏览器里查看「一切正常」「降级」「不可用」、引导部署各状态和三种日志各状态的界面——这些状态在没有宿主代理、真实服务器和出口的本机面板上看不到。它是开发和验收工具：**在演示里看到的任何东西都不算在真实主机上验证过**。

### 构建与打开

```sh
npm run demo:build        # tsc --noEmit && vite build --config vite.demo.config.ts → web/dist-demo/
npm run demo:serve        # vite preview：http://127.0.0.1:4174/（只是静态文件服务）
# 或任何静态文件服务器，例如：python3 -m http.server 4174 --bind 127.0.0.1 --directory dist-demo
npm run demo:dev          # 开发时：vite 开发服务器 http://127.0.0.1:5174/demo.html（改页面即时生效）
```

完全离线可用：页面、字体、数据都在 `dist-demo/` 里，没有任何外部资源；演示里的 `fetch` 被替换，`/api/*` 由浏览器内的演示 API 回答，其他地址一律拒绝，不发出任何网络请求。`file://` 直接打开时浏览器会拦截模块脚本，请用静态服务器。

### 选择场景、主题和页面

地址：`/?scenario=<场景>&theme=light|dark#/<页面>`（不带 `theme` 时跟随系统；页面就是面板自己的哈希路由）。页面底部固定的红色条（「演示数据」）上也能切换场景和主题；页面上还有淡淡的「演示数据 · 合成场景」水印，标签页标题以「【演示】」开头——截图不会被误认为真实面板。这条红色条为了不挡住内容，给页面底部加了与它等高的留白（宽窗口约 44 px，窄窗口折行时更高；只影响高度，不影响宽度）。

| 场景 `scenario=` | 显示什么 |
| --- | --- |
| `healthy` | 三种日志都在记录（解析日志已打开并安装：四台合成设备、约 190 条查询；连接日志 160 条连接、名字记录开；两者可以互相跳转；链路日志的时间线上有已恢复的握手超时和外部出口自检失败）。宿主通道正常，已安装且与拓扑一致；美国西岸出口的服务器经隧道地址管理（服务器页的「经隧道地址」列出推导的地址候选，含不可达的地址和原因）；两台国内中继按测得的质量分担（6:4）；主枢纽状态刚读过，七个地区组都有实际成员；全部服务器已测试连接（一台闲置服务器的指纹待确认）；解锁结果新鲜；嗅探服务运行中、有最近的决定；名单已更新；Mesh 备路已部署；远程接入三台设备 |
| `degraded` | 三种日志带观测缺口：连接日志提示嗅探服务上次没有正常退出；解析日志仍在记录但解析器换成了没有核对过的版本（显示原因和处理办法），有读晚了没有 MAC 的记录、时间不确定的记录、一个地址两个 MAC；链路日志有采集空窗、空窗后才发现的变化、合并的抖动（仍在计数）、读不到的来源和状态未知的对象。备用枢纽承载（`on_backup`），一台中继不通、另一台因丢包被剔除；香港机房 1 健康检查失败（组切到机房 2）；规则集 `rs07` 下载失败、保留旧版；英国出口的解锁结果三天前、已过期；备用枢纽和香港机房 2 有待安装的改动；两个枢纽的报告都已过时；一台服务器连接测试超时；一台远程设备三天没有握手 |
| `unavailable` | 第一次运行：没有宿主执行通道，什么都没装，没有服务器、密钥和账户（拓扑是同一份合成拓扑）；三种日志都读不到，各自说明原因 |
| `logs-off` | 三种日志都没有在记录：按域名嗅探没有开启；解析日志是默认的关闭状态（解析器已核对，可以打开）；链路日志的采集服务还没有随网关安装（只改三个日志页） |
| `logs-empty` | 三种日志都已安装并在运行，还没有一条记录：没有连接结束，审计文件是空的，链路日志只有基线（只改三个日志页） |
| `deploy-running` | 引导部署进行中：第一个出口已安装，第二个正在下发 |
| `deploy-rate-limited` | 服务器在 SSH 横幅前拒绝了面板的地址：这一步等待 `retry_after`（60 秒） |
| `deploy-compensated` | 一个出口下发失败并已补偿，运行停止 |
| `deploy-unknown` | 一个出口的回答无法读取：结果不明，运行停止 |
| `deploy-done` | 运行完成：四个节点在本次运行中安装，一个依据服务器上的安装记录采纳 |
| `deploy-verify` | 备用枢纽承载时的一次引导：两个节点按顺序安装，三个只需核对的节点单独成组——一台已核对并采纳，一台连不上（不挡住其它），一台在限速等待 |
| `deploy-skipped` | 一个出口预检被阻断、一个连不上，操作者跳过了它们；不依赖它们的出口继续安装，枢纽和网关继续等待并写明在等哪台 |
| `preflight-blocked` | 「部署」页的网关预检返回阻断项（FORWARD DROP、53 端口被占用、Docker） |
| `save-refused` | 整份拓扑保存被服务端以 `independent_resource_changed` 拒绝（任何「保存」都返回这条真实的拒绝） |

每个场景都含有规则集排除项已不存在（`rs03` 的 `removed-upstream.example`）的提示。

### 数据从哪里来

`src/demo/generated/*.json` 全部由 Go 的真实处理函数生成，不是手写的：`internal/api/demo_fixtures_test.go` 用合成拓扑（14 个节点：两台中继、主备枢纽、经中继出口的嵌套出口、外部 SOCKS 出口、九个出口；七个地区组；162 条有序规则——手工（其中一条钉死到外部 SOCKS 出口，所以网关对它有自己的自检）、导入、非手工；56 个规则集；14 个服务组；全部 41 个检测适配器在九个出口上的结果）和现有的测试替身（应答健康的宿主代理、假预检、进程内的 SSH 替身、假下载器/探测/上游/嗅探/远程接入/名单运行时、内存里的 Cloudflare 与 Mesh）启动 API，调用面板用到的每个读接口，按场景写出回答。地址只用文档地址段和私有网段，名字只用 `example`。

三种日志同样不是手写的记录，而是真实的服务代码在合成输入上的结果：连接日志是 `sniff.Journal` 里的合成连接；解析日志由真实的读取服务（`dnsjournal.Daemon`）读一份按观察到的行格式写的合成审计文件得到（时区推定、MAC 查询、半行计数都是它自己做的）；链路日志由真实的采集服务（`linkjournal.Collector`）按演示拓扑编译出的对象清单读合成的故障切换记录、握手时间、单元状态和自检结果，在生成器推进的时钟上记两小时。每份日志生成为一整页；筛选、翻页和两份日志之间的跳转由浏览器内的演示接口在这份列表上按服务的规则回答（`src/demo/api.ts`「the logs」），不编造记录。各场景的含义见 `docs/logging.md`「演示数据」。

重新生成（在仓库根目录）。生成对时钟敏感：合成记录按生成时刻的整分钟排布、时间按分钟取整，所以**在整分钟刚过时开始**（整个生成约 25 秒，要在同一分钟内跑完）；这样两次运行之间文件不变，否则会有相差一分钟的时间值：

```sh
npm --prefix web run demo:fixtures
# 即：MERIDIAN_DEMO_FIXTURES=write go test ./internal/api -run 'TestDemoFixtures$' -count=1
```

生成器把时间换成相对固定锚点的偏移（演示加载时再平移到「现在」，相对时间保持不变），把随机值（ID、密钥、指纹、摘要）换成形状相同的固定值，把证书正文换成一行占位（它的长度每次都不一样）。不带环境变量时 `go test ./...` 会在内存里重新生成一遍，并检查提交的文件和处理函数现在的回答结构一致（字段与类型）：后端改了回答结构而没有重新生成，测试就失败。

### 演示里的操作

只读：读接口返回生成的回答；面板为显示状态发的只读 POST（比较、校验、分配、网关预检、规则测试——只有生成过的几个示例名字）也返回生成的回答；「读取枢纽状态」返回已存的状态。**所有修改都不执行**：返回 403 `demo_read_only`「演示模式下不执行……」，由面板统一的错误提示显示。没有定时器假装长时间的操作。

### 与生产隔离

- 生产入口 `index.html` → `src/main.tsx` 不导入 `src/demo/` 下的任何模块；生产面板没有任何运行时开关、URL 参数、环境变量或路由能到达演示数据。
- 演示有自己的入口 `demo.html`、自己的构建配置 `vite.demo.config.ts` 和输出目录 `dist-demo/`（已加入 `.gitignore`、`.dockerignore`）；`npm run build` 的输出 `dist/` 与演示无关。
- Go 二进制只服务 `MERIDIAN_WEB_DIR`（`web/dist`），Docker 镜像只复制 `web/dist`。
- 自动检查：`src/demo/demo.test.tsx` 的 isolation 测试（生产入口的导入图、生产 HTML 与构建配置、Dockerfile 与 Go 源码、存在时的 `dist/` 内容）。
- 手工检查：

```sh
npm --prefix web run build
grep -rlE "MERIDIAN-DEMO-PREVIEW|演示数据|demo_read_only|__meridianDemo" web/dist   # 没有输出
grep -n "COPY --from=web" deploy/Dockerfile                                       # 只有 web/dist
grep -rn "dist-demo" --include=*.go cmd internal                                  # 没有输出
```

### 测试与布局检测

- `src/demo/demo.test.tsx`：`api.ts` 的每个接口都在演示路由表里，并且在每个场景里都有回答（生成的回答、未知对象的 404，或明确的演示拒绝），没有未处理的请求；三种日志（每个场景都有生成的回答、各场景代表的状态、解析日志和链路时间线的筛选与翻页、两个方向的跳转与处理函数生成的回答一致、没有数据的场景不显示基础场景的记录、数据只有演示地址和 `example` 名字）；标记条；隔离。约 2 秒。
- `src/demo/demo_pages_{healthy,degraded,unavailable,states}.test.tsx`：每个页面在三个主场景里各渲染一次、部分场景改变的页面在该场景里渲染一次，不出现页面错误边界、没有演示答不了的请求（`testkit.tsx`）；三个日志页在五个场景里各核对显示的是哪种状态（正常、观测缺口、读不到、关闭 / 没有安装、没有数据）。四个文件并行，单条最慢的是解锁页（约 3–5 秒，41 个适配器 × 9 个出口的矩阵；修复样式计算的选择器缓存之前是 11–13 秒），其余 0.5–2 秒。
- 布局检测脚本 `tools/ui-audit.js` 可以直接对演示运行，见 `docs/ui-layout.md`「Demo preview」。

## 首屏与拆包

面板由家里的网关在局域网里提供，网关经常没有到外网的路由，所以所有资源都随本地构建交付：没有 CDN、外部字体或脚本，拆出来的块也都在 `dist/assets/` 里。

**下面全是构建产物的测量**（`npm --prefix web run build`，2026-11-14，未压缩字节和 `gzip -9` 字节），不是浏览器里的加载时间。真实网关上的首屏时间、离线时在懒加载页面之间跳转、升级后旧标签页的表现，要在真实浏览器里检查，未检查前不算验证过。

### 规则

- 页面：每条路由一个懒加载块（`App.tsx` 的 `NAV`，`lazyPage`）。外壳只导入 `ui_base.tsx`；概览只导入 `status_words.tsx`，不再静态导入出口、服务器（连带密钥、预检）和 Mesh 页面。
- 第三方代码按模块图上的可达性分块（`web/chunks.ts`，由 `vite.config.ts` 的 `manualChunks` 调用），不维护包名或 antd 组件的清单：
  - `vendor-react`：React、ReactDOM、scheduler。只随 React 升级变化，跨面板版本可以一直缓存。
  - `vendor-shell`：入口经静态导入能到达的其余第三方模块（外壳、登录页、`ui_base.tsx` 用到的 antd）。
  - `vendor-pages`：只经懒加载页面到达、并且至少有 3 个页面用到的第三方模块（表格、选择框、分页、步骤条、数字输入……）。第一个需要它的页面加载它，之后缓存。
  - 其余（只有一两个页面用的，例如拓扑页的图形库 `@xyflow/react` 和 d3、远程接入页的二维码、规则页的上传）跟着那些页面走。
  - 「到达」按真实导入的名字算：`import { Button } from "antd"` 到达的是 antd 的按钮模块，不是 antd 入口再导出的全部组件（否则入口会「到达」整个 antd，什么都拆不出去）。CSS 不受这条规则影响，加载顺序与之前相同（入口一份 `index-*.css`，拓扑页自己一份）。
- 应用自己的代码交给 Rollup 按页面拆；`experimentalMinChunkSize: 3000` 把 Rollup 会拆出的几百字节的小块（单个图标、小工具函数）并到邻近的块里。
- 块数目标：约 20 个 JS 文件，登录页 3 个 JS + 1 个 CSS，进入概览再加 6 个。网关用一个连接依次送文件，几十个小文件的往返比多出来的几十 KB 更慢；反过来，一个 1 MB 的块让登录页也要下载并解析全部 antd。

### 入口与首屏（之前：HEAD `0e18232`；之后：本版）

| | 之前 | 之后 |
| --- | --- | --- |
| 入口块 `index-*.js` | 1,087,796 B / gzip 343,682 B | 46,301 B / gzip 17,771 B（外壳、登录页、`ui_base`、`state`、`api`） |
| 登录页要下载的（HTML 引用的全部） | `index-*.js` + `index-*.css`：1,127,876 B / gzip 351,589 B，2 个文件 | `index-*.js` + `vendor-react` + `vendor-shell` + `index-*.css`：831,176 B / gzip 262,646 B，4 个文件 |
| 登录 → 概览一共下载 | 1,404,722 B / gzip 448,306 B，20 个文件（概览静态导入了出口、服务器、密钥、预检、Mesh 页面和 10 个小共享块） | 1,260,420 B / gzip 397,765 B，10 个文件（概览、`ui`、`vendor-pages`、`RelaySharing`、`Sniff`、`status_words`） |
| 文件总数 / 总大小 | 30 个 JS + 2 个 CSS，1,957,770 B / gzip 637,551 B | 23 个 JS + 2 个 CSS，1,957,975 B / gzip 636,404 B |

入口块之前装了什么、为什么：`App.tsx` 从 `ui.tsx` 导入了 6 个外壳用的组件，而 `ui.tsx` 同时导入 antd 的 `Table`（连带 `rc-table`，以及表格筛选用的 `rc-tree`）、`Pagination`、`Select`、`Modal`、`Popover`，于是这些全部进了入口；加上外壳本身的 `Form`（`rc-field-form`、`async-validator`）、`Input`、`Menu`、`Result`、`Layout`、`Drawer`、`Dropdown`、cssinjs 和 ReactDOM。按模块统计（压缩前）：antd 约 954 KB、react-dom 134 KB、rc-table 109 KB、rc-tree 95 KB、rc-select 88 KB、rc-field-form 81 KB、rc-menu 61 KB、`ui.tsx` 52 KB。图标没有整套导入（按名字导入，树摇有效）；二维码和拓扑图形库原来就只在各自页面的块里。

### 各块（之前 → 之后，未压缩 / gzip）

| 之前 | B | gzip | 之后 | B | gzip |
| --- | ---: | ---: | --- | ---: | ---: |
| `index`（入口） | 1,087,796 | 343,682 | `index`（入口） | 46,301 | 17,771 |
| | | | `vendor-react` | 142,308 | 45,519 |
| | | | `vendor-shell` | 602,487 | 191,449 |
| | | | `vendor-pages` | 369,660 | 111,597 |
| `TopologyPage` | 239,683 | 79,668 | `TopologyPage` | 239,484 | 79,584 |
| `RulesPage` | 97,364 | 33,223 | `RulesPage` | 97,179 | 33,149 |
| `DeployPage` | 60,474 | 20,328 | `DeployPage` | 60,331 | 20,259 |
| `ExitsPage` | 57,019 | 19,854 | `ExitsPage` | 53,835 | 18,826 |
| `ServersPage` | 46,670 | 15,938 | `ServersPage` | 33,711 | 11,799 |
| `RemotePage` | 43,363 | 16,388 | `RemotePage` | 43,297 | 16,356 |
| `UnlockPage` | 41,824 | 14,616 | `UnlockPage` | 41,855 | 14,628 |
| `CredentialsPage` | 31,277 | 10,036 | `CredentialsPage` | 31,341 | 10,057 |
| `Withdraw` | 28,690 | 10,481 | `Withdraw` | 28,750 | 10,515 |
| `index`（共享块） | 24,545 | 8,328 | `ui`（共享：`ui.tsx`） | 19,556 | 7,646 |
| `index`（共享块） | 23,291 | 6,161 | `CloudflarePage`（含 `MeshDeploy`） | 22,823 | 8,216 |
| `RelaySharing` | 16,344 | 6,355 | `RelaySharing` | 14,811 | 5,598 |
| `progress` | 16,288 | 5,932 | `OverviewPage` | 13,911 | 5,048 |
| `OverviewPage` | 14,258 | 5,223 | `Preflight` | 12,816 | 4,777 |
| `MeshDeploy` | 13,397 | 5,050 | `ListsPage` | 11,018 | 4,909 |
| `ListsPage` | 10,871 | 4,838 | `Sniff` | 7,161 | 3,257 |
| `Collapse` | 10,792 | 3,971 | `status_words` | 4,145 | 1,973 |
| `CloudflarePage` | 10,286 | 4,296 | `LeakPage` | 3,579 | 2,003 |
| `index`（共享块） | 7,935 | 2,689 | `index`（共享块：出口页和拓扑页用的 antd `AutoComplete`） | 1,667 | 905 |
| `Sniff` | 7,050 | 3,198 | | | |
| `index`（共享块） | 4,375 | 1,672 | | | |
| `LeakPage` | 3,433 | 1,934 | | | |
| `ArrowUpOutlined` `types` `DeleteOutlined` `InfoCircleOutlined` `DownloadOutlined` `StopOutlined` `PlusOutlined`（7 个小块） | 4,796 | 3,127 | | | |
| `index-*.css` | 40,080 | 7,907 | `index-*.css` | 40,080 | 7,907 |
| `TopologyPage-*.css` | 15,869 | 2,656 | `TopologyPage-*.css` | 15,869 | 2,656 |

`vendor-shell` 仍有约 600 KB：外壳确实要用 antd 的 `Layout`、`Menu`、`Drawer`、`Dropdown`、`Form`、`Input`、`Result`、`Typography`、`App`（含消息和确认框）和 cssinjs。块之间的静态导入只有一个方向（页面 → `ui` → `vendor-pages` → `vendor-shell` → `vendor-react`），没有循环。

隔离不变：`src/demo/demo.test.tsx` 的隔离测试仍然沿着懒加载路由检查生产入口的整个导入图（`lazyPage(() => import(...))` 照样被跟踪）；`vite.config.ts` 和 `chunks.ts` 里没有任何演示相关的内容；`npm run demo:build` 照常构建到 `dist-demo/`；Dockerfile 和 Go 程序不受影响（Dockerfile 复制整个 `web/`，`chunks.ts` 在内）。

### 本版复测（2026-11-16）

上面两张表是 2026-11-14 拆包时的前后对照，留作那次改动的记录。之后加了解析设置、三个日志页、升级提示、凭据版本等，下面是这一版的构建（`npm --prefix web run build`，同样的量法：未压缩字节 / `gzip -9` 字节）。拆包规则没有变；仍然只是构建产物的测量，不是浏览器里的加载时间。

| | 2026-11-14 | 本版 |
| --- | --- | --- |
| 入口块 `index-*.js` | 46,301 B / gzip 17,771 B | 51,346 B / gzip 19,278 B（外壳这期间多了导航入口、升级提示 `PanelUpdate` 等） |
| 登录页要下载的（HTML 引用的全部） | 831,176 B / gzip 262,646 B，4 个文件 | 842,510 B / gzip 265,610 B，4 个文件 |
| 登录 → 概览一共下载 | 1,260,420 B / gzip 397,765 B，10 个文件 | 1,286,332 B / gzip 406,186 B，10 个文件（同样的六个块） |
| 文件总数 / 总大小 | 23 个 JS + 2 个 CSS，1,957,975 B / gzip 636,404 B | 28 个 JS + 2 个 CSS，2,103,494 B / gzip 688,378 B |

新增的块（都只在打开对应页面时下载；从概览进入时除自己以外只多一个共享的 `log_common`）：

| 块 | B | gzip | 说明 |
| --- | ---: | ---: | --- |
| `DNSView` | 25,363 | 9,108 | 解析设置页 |
| `DNSLogsPage` | 22,916 | 8,751 | 解析日志页 |
| `ConnectionLogsPage` | 19,829 | 7,402 | 连接日志页（设备连接日志从嗅探卡片搬出） |
| `LinkLogsPage` | 19,670 | 7,313 | 链路日志页 |
| `log_common` | 5,607 | 2,626 | 三个日志页共用：开头两句话、空状态、范围列表、跳转面板 |

与 2026-11-14 相比变化较大的原有块（两次测量之间有多轮改动，没有逐个提交追究原因）：`Sniff` 7,161 → 18,151 B（gzip 3,257 → 7,315；它仍在概览的首屏闭包里），`DeployPage` 60,331 → 71,400 B（gzip 20,259 → 23,262），`ServersPage` 33,711 → 40,688 B，`Preflight` 12,816 → 17,894 B，`index-*.css` 40,080 → 42,819 B（gzip 7,907 → 8,361），`vendor-shell` 602,487 → 606,037 B；`vendor-react`、`vendor-pages`、`TopologyPage`、`RulesPage`、`ExitsPage` 基本不变。

复测：`npm --prefix web run build` 后对 `dist/assets/` 下每个文件取字节数和 `gzip -9` 后的字节数；首屏是 `dist/index.html` 引用的文件加上它们的静态 `import`，概览再加 `OverviewPage-*.js` 的静态 `import` 闭包。

## 前端测试耗时

**测量方式**：`cd web && /usr/bin/time -p npx vitest run --reporter=json --outputFile=…`，机器上没有别的 vite / vitest 进程（开发机，M3 Max 16 核，后台负载约 3–4），vitest 默认的并行度。之前是 HEAD `0e18232`，之后是本版。

| | 之前 | 之后 |
| --- | --- | --- |
| 整套墙钟 | 325.2 s | 21.0 s |
| 各用例耗时之和 | 650.6 s | 164.9 s |
| 文件 / 用例 | 17 / 272 | 21 / 277（新增 `lazy_routes.test.tsx` 的 5 条；`pages.test.tsx` 的 95 条分到 4 个文件，一条不少） |
| 超过 10 s 的用例 | 16 | 0 |
| 超过 5 s 的用例 | 39 | 3（最慢 5.2 s） |

目标是没有超过 10 秒的用例、整套在一分钟以内；结果是最慢 5.2 秒、整套 21 秒。超时（30 s）、断言和用例都没有改。

### 原因

1. **jsdom 的样式计算每次都重新编译全部选择器（主因）**。jsdom 的 `getComputedStyle` 拿元素和每个样式表的每条规则逐一匹配，匹配用 nwsapi；nwsapi 把编译好的选择器放在一个 1000 条的 LRU 缓存里，而 antd 注入的样式表里不同的选择器多于 1000 条，层叠计算又每次按同样的顺序走一遍，于是每次查找都未命中，每次 `getComputedStyle` 都把所有选择器重新解析、编译一遍（约 25 ms 一次）。Testing Library 的 `getByRole` / `findByRole`（带 `name`）为了跳过隐藏元素，要对每个候选元素算样式，`waitFor` 每 50 ms 重来一次。对最慢的用例（部署页「explains refusals by their code」，24 s）做 CPU 采样：86 % 的时间在 `getComputedStyle` 里，其中大部分是 nwsapi 的 `parse` / `compile`。
   修复：`test-setup.ts` 用同一份 nwsapi 源码创建一个缓存足够大的实例，配置与 jsdom 相同，换下 jsdom 给样式计算用的那个实例（`document._nwsapiDontThrow`）。匹配结果不变（缓存里只有编译好的选择器，不是匹配结果），只是不再重复编译。这条用例从 13.7 s（单独跑）降到 1.7 s；整套墙钟从 325 s 降到 52 s。如果 jsdom 或 nwsapi 升级后结构变了，setup 会直接报错而不是悄悄变慢。没有新增依赖。
2. **一个文件装了一半的页面用例，不能并行**。`pages.test.tsx` 有 95 条用例，单个 worker 串行跑 322 s，整套的墙钟就是它（修了第 1 条以后它仍要 49 s，其他文件 15 s 内都结束了）。按页面拆成 4 个文件，帮助函数和合成数据移到 `pages_fixtures.tsx`；整套墙钟 52 s → 21 s。
3. 检查过、不是主要原因的：没有假计时器；只有 4 处 50 ms 的真实等待（确认一个不应发生的请求在这段时间里确实没有发生，删掉就不再检查这一点）；`userEvent.type` 输入的都是十几个字符以内的值；夹具是普通函数、构造很便宜；整页渲染在每条用例里只做一次。

剩下最慢的几条（3–5 s）：演示数据下的解锁页（41 个适配器 × 9 个出口的矩阵）和 165 条规则的规则页。采样显示时间花在 React 提交这么大的页面（约 1.2 s）和 antd 第一次为这个文件注册组件样式（cssinjs 往 jsdom 里写 `<style>`，约 1.2 s），是渲染本身的工作量。

### 各文件（墙钟，秒；「最慢」是该文件里最慢的一条）

| 文件 | 之前用例 | 之前 | 之前最慢 | 之后用例 | 之后 | 之后最慢 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `pages.test.tsx` | 95 | 322.6 | 24.1 | — | — | — |
| `pages_rules_topology.test.tsx` | — | — | — | 20 | 18.6 | 2.6 |
| `pages_exits.test.tsx` | — | — | — | 34 | 17.3 | 2.1 |
| `pages_deploy.test.tsx` | — | — | — | 28 | 14.1 | 3.1 |
| `pages_remote_unlock.test.tsx` | — | — | — | 13 | 9.6 | 2.8 |
| `rules_ordered.test.tsx` | 11 | 87.5 | 16.0 | 11 | 15.7 | 2.6 |
| `panel.test.tsx` | 18 | 48.7 | 7.8 | 18 | 12.8 | 4.6 |
| `layout_pages.test.tsx` | 10 | 33.3 | 7.6 | 10 | 15.7 | 5.1 |
| `demo/demo_pages_healthy.test.tsx` | 12 | 31.6 | 13.9 | 12 | 11.8 | 5.1 |
| `demo/demo_pages_degraded.test.tsx` | 12 | 31.3 | 13.4 | 12 | 12.0 | 5.2 |
| `demo/demo_pages_unavailable.test.tsx` | 12 | 23.9 | 11.9 | 12 | 8.4 | 3.4 |
| `demo/demo_pages_states.test.tsx` | 13 | 21.6 | 3.5 | 13 | 8.4 | 2.0 |
| `channels.test.tsx` | 4 | 12.6 | 9.7 | 4 | 3.2 | 2.3 |
| `table_budget.test.tsx` | 10 | 11.4 | 3.5 | 10 | 3.7 | 1.1 |
| `second_pass.test.tsx` | 3 | 8.3 | 7.5 | 3 | 2.5 | 1.8 |
| `demo/demo_phone.test.tsx` | 5 | 7.9 | 6.8 | 5 | 5.5 | 4.5 |
| `ui_layout.test.tsx` | 34 | 4.7 | 1.0 | 34 | 1.7 | 0.3 |
| `deployment_guide.test.tsx` | 7 | 3.8 | 1.3 | 7 | 1.1 | 0.4 |
| `lazy_routes.test.tsx` | — | — | — | 5 | 1.1 | 0.5 |
| `unlock_routing.test.tsx` | 2 | 0.9 | 0.9 | 2 | 0.4 | 0.4 |
| `demo/demo.test.tsx` | 19 | 0.6 | 0.1 | 19 | 0.9 | 0.3 |
| `topology_contract.test.tsx` | 5 | 0.2 | 0.1 | 5 | 0.2 | 0.1 |

之后的单文件墙钟比单独跑时长：21 个文件同时在 15 个 worker 上跑，互相抢 CPU。

### 之前最慢的 20 条（秒）

| 之前 | 之后 | 用例 |
| ---: | ---: | --- |
| 24.1 | 3.1 | deploy › explains refusals by their code（现 `pages_deploy`） |
| 16.0 | 2.6 | rules: remaining gaps › shows a rule-set's exclusions …（`rules_ordered`） |
| 15.8 | 2.0 | topology: deleting a deployed node › offers 仅从拓扑删除 and 先撤回再删除 …（现 `pages_rules_topology`） |
| 13.9 | 2.2 | rules: remaining gaps › accepts every row of one code at once …（`rules_ordered`） |
| 13.9 | 5.1 | demo pages: healthy › #/unlock renders |
| 13.4 | 5.2 | demo pages: degraded › #/unlock renders |
| 13.1 | 2.2 | rules: remaining gaps › shows only the kind of a rule-set's credential …（`rules_ordered`） |
| 13.0 | 2.8 | remote access › shows the one-time configuration once …（现 `pages_remote_unlock`） |
| 12.4 | 2.3 | rules: import from mihomo › previews in order …（`rules_ordered`） |
| 12.0 | 2.0 | nested and external SOCKS exits › adds an external exit …（现 `pages_exits`） |
| 11.9 | 3.4 | demo pages: unavailable › #/unlock renders |
| 11.8 | 2.1 | domestic relays sharing the main path › edits the thresholds and the probe budget …（现 `pages_exits`） |
| 11.2 | 2.6 | rules › adds a rule with exactly one target and no mode …（现 `pages_rules_topology`） |
| 11.2 | 1.9 | gateway settings: resolver › shows both DNS settings off …（现 `pages_rules_topology`） |
| 10.8 | 1.5 | topology: deleting a node › lists what refers to the node …（现 `pages_rules_topology`） |
| 10.6 | 1.6 | gateway settings: resolver › turns a setting back off（现 `pages_rules_topology`） |
| 9.7 | 2.3 | servers: management channel › edits the channel to a jump through a relay …（`channels`） |
| 7.9 | 1.5 | rules › puts a requirement mismatch from validation on the field …（现 `pages_rules_topology`） |
| 7.8 | 1.8 | secrets › shows a set API token as 已设置 · 替换 …（`panel`） |
| 7.8 | 0.6 | deploy: gateway install pre-check › requires a reviewed pre-check …（现 `pages_deploy`） |

### 移动过的用例

没有拆开或改写任何一条用例；`pages.test.tsx` 的 36 个 `describe` 块原样分到 4 个文件（逐行比对过：除了文件头的导入和夹具声明前加的 `export`，没有一行增减）：

- `pages_exits.test.tsx`：region groups；region groups: the hub's actual state；region groups with the same name；primary and backup hub；domestic relays sharing the main path；nested and external SOCKS exits；SOCKS credentials；overview: first-time order and all region groups；overview: unlock probe channel。
- `pages_deploy.test.tsx`：deploy；deploy: remote nodes；deploy: install pre-check for remote nodes；deploy: panel-delivered binaries；deploy: gateway install pre-check；servers: login help；deploy: deployment records and withdraw；deploy: managed sysctl after an install；ssh rate limiting。
- `pages_rules_topology.test.tsx`：rules；unsaved-changes guard；topology；gateway settings: resolver；rules: ordering；topology: deleting a node；topology: deleting a deployed node；rules: same-named region groups；ports；WSS carriers: random path and pinned self-signed certificate。
- `acceptance.test.tsx`：acceptance page（影响与耗时、各部分分开、过期不计、一键执行、演练的后果与二次确认、过期的确认、签收、恢复未核验的阻断、手机宽度）；acceptance links on other pages（防泄露逐行链接与记录、部署页的状态、读不到摘要时仍有链接）。
- `pages_remote_unlock.test.tsx`：remote access；remote access: configuration text；unlock；leak check；unlock: not applicable is not unknown；tables at narrow widths；unlock: results of removed exits；unlock: TCP-only external exits。
- `pages_fixtures.tsx`：原文件顶层的帮助函数（`btn`、`confirmModal`、`pick`、`menuItem`）和合成数据构造函数 / 常量，原样导出。

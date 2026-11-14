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

- 侧栏分组：概览 `#/` · 网络（拓扑 `#/topology`、出口 `#/exits`、分流规则 `#/rules`、名单 `#/lists`）· 资源（服务器 `#/servers`、密钥 `#/keys`、Cloudflare `#/cloudflare`）· 接入（远程接入 `#/remote`）· 运维（部署 `#/deploy`、解锁 `#/unlock`、防泄露 `#/leak`）。路由表是 `App.tsx` 里的 `NAV`，页面都是 `React.lazy` 按路由拆包。窄于 `lg` 时侧栏变成抽屉。
- 哈希路由，自己实现，没有路由库：`useRouter()` 给出 `route.page`、`route.params`（`#/servers/srv-1` → `["srv-1"]`）、`route.query`，`navigate(href("servers", id))` 跳转。对象链接一律 `href(page, id)`：节点 `#/topology/<node>`、服务器 `#/servers/<id>`、密钥 `#/keys/<id>`、地区组 `#/exits/<id>`、规则 `#/rules/<id>`、设备 `#/remote/<id>`、Mesh 部署 `#/cloudflare?section=mesh`。页面用 `route.params[0]` 打开对应对象的详情抽屉。
- 顶栏：宿主执行通道是否可用、数据面安装版本或「数据面未安装」、未完成的安装事务、进行中的任务（名单更新、解锁探测、Mesh 部署/撤回），以及常驻的「有改动尚未安装 / 已应用，尚未安装 / 尚未安装到网关 / 拓扑无法编译」。这些都来自一个只读接口 `GET /api/status`（`useStatus()`：`status`、`install`、`jobs`；平时 20 秒、有任务运行时 5 秒轮询一次）。它和**已安装清单**比较，不是和上一次「应用」的快照比较，所以「应用但没安装」也会显示待安装。**只改文档的修改（API 返回 `apply_required: true`）之后调用 `useStatus().markApplyRequired()`**，顶栏立即显示待安装。
- 拓扑文档：`useTopologyDoc()` 持有整份拓扑的工作副本（`topo`、`setTopo`、`dirty`、`save(draft)`、`validate()`、`reload()`、`issues`、`paths`）。编辑整份文档的页面放 `<TopologyDocBar/>`（校验 / 放弃 / 保存草稿 / 保存，并自动注册离开提示）。**用其他 API 改了存储里的文档（名单策略、地区组、远程接入……）之后调用 `applyServerChange(t => …)`，把同样的改动应用到工作副本**，否则之后整份保存会把旧值写回去。
- 离开提示：`useUnsavedGuard(dirty, message?)`，覆盖站内跳转、浏览器前进后退和关闭标签页。

### 共享组件（`ui.tsx`）

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

## 页面

| 路由 | 文件 | 内容 |
| --- | --- | --- |
| `#/` | `OverviewPage` | 状态和下一步（含「远端节点第一次装机」：还没有公钥的远端节点数，链到「部署 → 远端节点」）；地区组卡片显示总数，超过 6 个时有「还有 N 个 · 查看全部」 |
| `#/topology` | `TopologyPage` | 画布 + 右侧抽屉编辑节点/链路；删除节点时列出引用它的链路、地区组（变空组、失去手动指定时各有一句后果）、钉到它的规则（逐条选择改指向或删除，不选不能删）和关联的服务器，一步清理（`deleteNode`）；节点选择服务器（没有 `ssh_*` 输入）；「网关设置」抽屉（局域网、转运前缀、NAT64 预留……）；可点击的校验问题；`#/topology/<节点或链路>` 打开对应对象 |
| `#/exits` | `ExitsPage` | 按地区分区的地区组卡片：自动/手动、成员排序（拖动或上下箭头，一次 PATCH 保存整个顺序）、实际顺序和排除原因、手动指定和失败时行为、实际使用（只来自枢纽报告 `actual.state == "ok"`，其余显示未知和原因）与面板推算分两行、顶部「枢纽运行状态」条和读取按钮、默认组、删除被引用时列出引用者；不在任何组里的出口 |
| `#/rules` | `RulesPage` | 规则表按编译器的匹配顺序显示（`effectiveOrder`：手动规则总在内置规则前，再按优先级、ID）；上下移动和「…」里的移到最前 / 最后只在同一类里移动（`moveRule`：邻居之间有空位只改被移动的那条，否则把这一类按显示顺序以 10 为步长重编号，内置规则数值变了标「已改默认」）；去向是地区组或固定出口二选一；抽屉编辑并先调 `/api/validate` 把本规则的错误放到字段上；规则没有模式字段 |
| `#/lists` | `ListsPage` | 名单源和更新 |
| `#/servers` `#/keys` `#/cloudflare` | | 资源 |
| `#/remote` | `RemotePage` | 入口设置、路由器转发说明、设备表（运行状态或读不到的原因、配置过期）、一次性配置对话框（文本、复制、下载、浏览器本地生成的二维码、必须确认才能关闭、关闭即丢弃）、重新生成、停用、删除 |
| `#/deploy` | `DeployPage` | 待安装的改动（按节点、按文件的差分；「已应用但未安装」时改列 `/api/diff` 的 `installed`：安装会新增/修改/删除的网关文件，按哈希，没有逐行内容）、安装到本机（拒绝和失败一律按错误体的 `code` 解释，不匹配文字；`peer_keys_missing` 把每个对端链接到修它的地方）、「只写入数据目录」只在没有宿主执行通道时提供、回滚（`previous_available=false` 时不提供；已安装只提供含宿主网络，未安装只提供快照）、远端节点（推荐顺序、没有公钥的节点标「第一次装机」且主按钮是「生成密钥并下发」，`?section=remote` 滚到这里）、当前安装 |
| `#/unlock` | `UnlockPage` | 未验证声明、发起探测（服务、按组/出口、地址族、取消）、结果矩阵（服务 × 组/出口 × 地址族；「仅可达」与「解锁」颜色和文字都不同；只支持 IPv4 的服务在 IPv6 上是「不适用 · 仅 IPv4」，不算未知，旧记录里 `unknown` + `family_not_supported` 也这样显示）、每个服务当前所在出口、历史、平台目录 |
| `#/leak` | `LeakPage` | 四组检查；集成和人工两组无论接口返回什么都固定显示「未执行」/「待人工签收」 |

测试：`panel.test.tsx`（资源页、名单、顶栏）和 `pages.test.tsx`（上面这些页面的关键交互）。

## 演示预览（只用于开发和验收）

用合成数据驱动**真实的外壳和页面**，在浏览器里查看「一切正常」「降级」「不可用」和引导部署各状态的界面——这些状态在没有宿主代理、真实服务器和出口的本机面板上看不到。它是开发和验收工具：**在演示里看到的任何东西都不算在真实主机上验证过**。

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
| `healthy` | 宿主通道正常，已安装且与拓扑一致；两台国内中继按测得的质量分担（6:4）；主枢纽状态刚读过，七个地区组都有实际成员；全部服务器已测试连接（一台闲置服务器的指纹待确认）；解锁结果新鲜；嗅探服务运行中、有最近的决定；名单已更新；Mesh 备路已部署；远程接入三台设备 |
| `degraded` | 备用枢纽承载（`on_backup`），一台中继不通、另一台因丢包被剔除；香港机房 1 健康检查失败（组切到机房 2）；规则集 `rs07` 下载失败、保留旧版；英国出口的解锁结果三天前、已过期；备用枢纽和香港机房 2 有待安装的改动；两个枢纽的报告都已过时；一台服务器连接测试超时；一台远程设备三天没有握手 |
| `unavailable` | 第一次运行：没有宿主执行通道，什么都没装，没有服务器、密钥和账户（拓扑是同一份合成拓扑） |
| `deploy-running` | 引导部署进行中：第一个出口已安装，第二个正在下发 |
| `deploy-rate-limited` | 服务器在 SSH 横幅前拒绝了面板的地址：这一步等待 `retry_after`（60 秒） |
| `deploy-compensated` | 一个出口装机失败并已补偿，运行停止 |
| `deploy-unknown` | 一个出口的回答无法读取：结果不明，运行停止 |
| `deploy-done` | 运行完成：四个节点在本次运行中安装，一个依据服务器上的安装记录采纳 |
| `preflight-blocked` | 「部署」页的网关预检返回阻断项（FORWARD DROP、53 端口被占用、Docker） |
| `save-refused` | 整份拓扑保存被服务端以 `independent_resource_changed` 拒绝（任何「保存」都返回这条真实的拒绝） |

每个场景都含有规则集排除项已不存在（`rs03` 的 `removed-upstream.example`）的提示。

### 数据从哪里来

`src/demo/generated/*.json` 全部由 Go 的真实处理函数生成，不是手写的：`internal/api/demo_fixtures_test.go` 用合成拓扑（14 个节点：两台中继、主备枢纽、经中继出口的嵌套出口、外部 SOCKS 出口、九个出口；七个地区组；166 条有序规则——手工、导入、非手工；56 个规则集；14 个服务组；全部 41 个检测适配器在九个出口上的结果）和现有的测试替身（应答健康的宿主代理、假预检、进程内的 SSH 替身、假下载器/探测/上游/嗅探/远程接入/名单运行时、内存里的 Cloudflare 与 Mesh）启动 API，调用面板用到的每个读接口，按场景写出回答。地址只用文档地址段和私有网段，名字只用 `example`。重新生成（在仓库根目录，确定性：两次运行之间文件不变）：

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

- `src/demo/demo.test.tsx`：`api.ts` 的每个接口都在演示路由表里，并且在每个场景里都有回答（生成的回答、未知对象的 404，或明确的演示拒绝），没有未处理的请求；标记条；隔离。约 2 秒。
- `src/demo/demo_pages_{healthy,degraded,unavailable,states}.test.tsx`：每个页面在三个主场景里各渲染一次、部分场景改变的页面在该场景里渲染一次，不出现页面错误边界、没有演示答不了的请求（`testkit.tsx`）。四个文件并行，单条最慢的是解锁页（约 11–13 秒，41 个适配器 × 9 个出口的矩阵），其余 0.5–4 秒。
- 布局检测脚本 `tools/ui-audit.js` 可以直接对演示运行，见 `docs/ui-layout.md`「Demo preview」。


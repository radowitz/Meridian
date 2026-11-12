# Meridian 控制面板（web/）

React 18 + Vite + TypeScript + antd 5。界面文字全部中文，用语跟 `docs/` 一致。

```sh
npm ci
npm run dev      # 开发服务器，/api 代理到 127.0.0.1:8787（make run）
npm run build    # tsc --noEmit && vite build → dist/
npm test         # vitest + Testing Library + jsdom，对着内存里的假 API
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
| `#/` | `OverviewPage` | 状态和下一步 |
| `#/topology` | `TopologyPage` | 画布 + 右侧抽屉编辑节点/链路；节点选择服务器（没有 `ssh_*` 输入）；「网关设置」抽屉（局域网、转运前缀、NAT64 预留……）；可点击的校验问题；`#/topology/<节点或链路>` 打开对应对象 |
| `#/exits` | `ExitsPage` | 按地区分区的地区组卡片：自动/手动、成员排序（拖动或上下箭头，一次 PATCH 保存整个顺序）、实际顺序和排除原因、手动指定和失败时行为、实际使用（面板推算 / 未验证）、默认组、删除被引用时列出引用者；不在任何组里的出口 |
| `#/rules` | `RulesPage` | 规则表（优先级顺序、去向是地区组或固定出口二选一、启用、内置/手动），抽屉编辑并先调 `/api/validate` 把本规则的错误放到字段上；规则没有模式字段 |
| `#/lists` | `ListsPage` | 名单源和更新 |
| `#/servers` `#/keys` `#/cloudflare` | | 资源 |
| `#/remote` | `RemotePage` | 入口设置、路由器转发说明、设备表（运行状态或读不到的原因、配置过期）、一次性配置对话框（文本、复制、下载、浏览器本地生成的二维码、必须确认才能关闭、关闭即丢弃）、重新生成、停用、删除 |
| `#/deploy` | `DeployPage` | 待安装的改动（按节点、按文件的差分）、安装到本机（步骤、警告、资源差异、补偿/恢复、各种拒绝状态）、回滚（已安装只提供含宿主网络，未安装只提供快照）、远端节点预览/下发/轮换密钥、当前安装 |
| `#/unlock` | `UnlockPage` | 未验证声明、发起探测（服务、按组/出口、地址族、取消）、结果矩阵（服务 × 组/出口 × 地址族；「仅可达」与「解锁」颜色和文字都不同）、每个服务当前所在出口、历史、平台目录 |
| `#/leak` | `LeakPage` | 四组检查；集成和人工两组无论接口返回什么都固定显示「未执行」/「待人工签收」 |

测试：`panel.test.tsx`（资源页、名单、顶栏）和 `pages.test.tsx`（上面这些页面的关键交互）。

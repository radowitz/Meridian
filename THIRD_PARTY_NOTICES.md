# 第三方组件与许可

Meridian 自身的代码以 **AGPL-3.0-only** 发布（仓库根目录 `LICENSE`）。本文列出面板**打包进镜像**、**下发到主机**、**在主机上安装或拉取**的第三方组件，以及构建时链接的依赖。整理日期 2026-11-18，以仓库里锁定的版本为准（`internal/artifacts/artifacts.lock`、`go.mod`、`web/package-lock.json`、`deploy/Dockerfile`、`deploy/docker-compose.yml`）。

本文是整理结果，不是法律意见；标 **待确认** 的条目在首次发布镜像前要由维护者核对。

## 1. 面板镜像里带着、并由面板下发到远端主机的二进制

版本和 SHA-256 只写在 `internal/artifacts/artifacts.lock`。镜像构建时下载（`deploy/fetch-artifacts.sh`）并放进 `/usr/share/meridian/artifacts`，面板经 SSH 传到主机。也就是说，**发布镜像就是在再分发这些二进制**。

| 组件 | 版本 | 上游 | 许可 | 用在哪里 | 再分发要做的事 |
|---|---|---|---|---|---|
| SmartDNS | 1.2026.08.05-0921（Release48.4），x86_64 / aarch64 静态可执行文件 | github.com/pymumu/smartdns | **GPL-3.0** | 远端出口的解析器（`meridian-smartdns.service`） | 见下面「兼容性要点」第 1 条：随镜像提供许可全文和对应源码（或书面源码提供） |
| wstunnel | 11.1.0，x86_64 / aarch64 | github.com/erebe/wstunnel | BSD-3-Clause | WG over WSS 的客户端与服务端（网关、中继、枢纽） | 保留版权声明和许可全文 |
| gost | 3.2.6，x86_64 / aarch64 | github.com/go-gost/gost | MIT | 外部 SOCKS 出口的承载节点上的透明重定向 | 保留版权声明和许可全文 |

## 2. 面板镜像的基础层（Debian 软件包）

运行镜像基于 `debian:13-slim`，额外装了 `ca-certificates`、`wireguard-tools`（GPL-2.0）、`nftables`（GPL-2.0）、`iproute2`（GPL-2.0）、`curl`（curl 许可，MIT 类）、`procps`（GPL-2.0 / LGPL）、`openssl`（Apache-2.0）。这些是 Debian 原样的二进制包，各自的版权文件在镜像的 `/usr/share/doc/<包>/copyright`。源码可从 Debian 归档按同一版本取得；发布镜像时在发布说明里写明这一点（GPL 包的源码提供义务，见兼容性要点第 2 条）。

构建阶段的 `node:22-bookworm`、`golang:1.22-bookworm` 不进运行镜像。

## 3. 由用户的主机自己拉取或安装（Meridian 不再分发）

| 组件 | 方式 | 许可 / 条款 | 说明 |
|---|---|---|---|
| SmartDNS 容器镜像 `pymumu/smartdns`（网关解析器） | `deploy/docker-compose.yml` 默认 `pymumu/smartdns:latest`，可用 `MERIDIAN_SMARTDNS_IMAGE` 指定；发布工作流只记录上游多架构摘要，不重建 | GPL-3.0 | 网关从 Docker Hub 拉取。按[安装文档](docs/user/install.md)离线导出镜像包再拷到网关时，是用户自己在复制，镜像包里附带上游镜像原样的内容 |
| Cloudflare WARP 客户端（`cloudflare-warp` 包，`warp-cli`） | Mesh 主机级连接器：面板在操作员确认后让远端主机从 `pkg.cloudflareclient.com` 的 apt 源安装 | Cloudflare 专有软件，受 Cloudflare 服务条款约束 | 不在仓库和镜像里；使用即接受 Cloudflare 的条款 |
| `cloudflare/mesh` 容器镜像 | Mesh sidecar，主机从 Docker Hub 拉取（可在拓扑 `mesh_image` 里钉住摘要） | Cloudflare 的条款 | 不在仓库和镜像里 |
| v2fly `domain-list-community`（geosite 数据） | 网关的「更新名单」从 jsDelivr 或 GitHub raw 下载，转成 SmartDNS 的域名集合 | MIT | 仓库和镜像里不带数据，只带下载地址 |
| `gaoyifan/china-operator-ip`（chnroute） | 同上，下载 IPv4 / IPv6 前缀列表 | **待确认**（上游仓库的许可声明） | 仓库和镜像里不带数据 |

## 4. 编译进 `meridian` 二进制的 Go 模块

来自 `go.mod`（直接依赖和它们被链接的间接依赖）：

| 模块 | 版本 | 许可 |
|---|---|---|
| golang.org/x/crypto | v0.31.0 | BSD-3-Clause |
| golang.org/x/sys | v0.28.0 | BSD-3-Clause |
| gopkg.in/yaml.v3 | v3.0.1 | MIT 与 Apache-2.0（双文件） |
| modernc.org/sqlite | v1.34.5 | BSD-3-Clause（内含的 SQLite 为公有领域） |
| modernc.org/libc | v1.55.3 | BSD-3-Clause（部分文件带 MIT 等宽松许可，见模块内 LICENSE-*） |
| modernc.org/mathutil | v1.6.0 | BSD-3-Clause |
| modernc.org/memory | v1.8.0 | BSD-3-Clause |
| github.com/dustin/go-humanize | v1.0.1 | MIT |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause |
| github.com/mattn/go-isatty | v0.0.20 | MIT |
| github.com/ncruces/go-strftime | v0.1.9 | MIT |
| github.com/remyoudompheng/bigfft | 2023-01-29 | BSD-3-Clause |

Go 标准库：BSD-3-Clause。全部宽松许可，要求在分发二进制时附带版权声明和许可全文。

## 5. 打包进面板前端（`web/dist`）的 npm 包

直接依赖（`web/package.json`）：`react` / `react-dom` 18.3.1（MIT）、`antd` 5.x（MIT）、`@ant-design/icons` 5.x（MIT）、`@xyflow/react` 12.x（MIT）。按 `web/package-lock.json`，运行时依赖树共 95 个包：MIT 86 个、ISC 8 个、BSD-3-Clause 1 个，没有 copyleft 许可。开发依赖（Vite、Vitest、TypeScript、Testing Library、jsdom 等）只在构建和测试时使用，不进产物。

## 6. 只做格式兼容、不使用代码的项目

- **mihomo / Clash 配置**：面板能导入 mihomo 的 YAML（`internal/mihomo/import.go`，用 `gopkg.in/yaml.v3` 解析），只读取格式，不包含、不链接、不调用 mihomo 的任何代码。mihomo 的许可（GPL-3.0）不因此适用于 Meridian。
- 解锁探测的适配器清单按三个公开检测脚本的地区清单逐项对照编写（见 `docs/unlock-methods.md`），是独立实现，没有复制脚本代码。**待确认**：维护者核对 `internal/unlock` 里没有逐字照搬的大段文本。

## 与 AGPL-3.0-only 的兼容性

结论：**没有发现不兼容的组件**。

- 链接进 `meridian` 二进制和前端产物的 Go / npm 依赖全部是宽松许可（MIT、BSD-2/3-Clause、ISC、Apache-2.0），都可以并入 AGPL-3.0 作品（Apache-2.0 与 GPLv3/AGPLv3 兼容）；分发时保留它们的版权声明和许可全文。
- SmartDNS（GPL-3.0）作为独立二进制随镜像下发、网关侧作为独立容器运行，与 Meridian 只经命令行、配置文件和网络交互，属于聚合；即使视为结合，GPL-3.0 第 13 条也明确允许与 AGPL-3.0 作品结合。
- wstunnel（BSD-3-Clause）、gost（MIT）：独立二进制，宽松许可，兼容。
- Debian 基础层的 GPL-2.0 软件包：独立程序，聚合，兼容（仍有源码提供义务）。
- Cloudflare WARP / `cloudflare/mesh`：专有，但由用户的服务器从 Cloudflare 官方源安装或拉取，Meridian 不分发、不链接，不构成许可冲突。
- 名单数据在运行时下载、不分发；chnroute 数据源许可仍待确认（不影响代码许可）。
- mihomo（GPL-3.0）只做格式兼容，不使用其代码。

## 兼容性要点

1. **SmartDNS 是 GPL-3.0，而镜像会再分发它的二进制。** Meridian 只把它作为独立程序传到主机、经命令行和配置文件使用，不链接，属于「聚合」，与 Meridian 的 AGPL-3.0-only 兼容。但发布镜像时必须：附上 GPL-3.0 全文；提供与二进制完全对应的源码（Release48.4 的源码包，最好随 GitHub Release 一起作为附件上传，或附带书面源码提供）；不对用户加额外限制。**这是首次发布前必须完成的事。**
2. **镜像里的 Debian GPL 软件包**（wireguard-tools、nftables、iproute2、procps）同样是再分发：在发布说明里写明对应的 Debian 版本和源码来源（Debian 归档）。
3. **wstunnel（BSD-3-Clause）和 gost（MIT）**：随镜像附上版权声明和许可全文；BSD-3 的第三条禁止用其作者名为 Meridian 背书。
4. **Cloudflare WARP 与 `cloudflare/mesh`** 是专有软件，Meridian 不分发，只让用户的主机从 Cloudflare 官方源安装；文档里要说明使用即接受 Cloudflare 条款。
5. **名单数据**（v2fly MIT；chnroute 待确认）在运行时下载，Meridian 不分发；若以后把名单快照打进镜像，要重新核对。
6. **建议的落实方式**（尚未实现）：镜像构建时把上面二进制的 LICENSE 文件和本文件复制到 `/usr/share/meridian/licenses/`，并在 Release 附件里上传 SmartDNS 对应源码包。见 [docs/open-source-checklist.md](docs/open-source-checklist.md)。

# 开源发布清单（维护者用）

这份清单列出把当前工作区作为公开仓库发布之前，**维护者本人**要做的决定和操作。代码和文档里能做的清理已经完成（见 [privacy-inventory.md](privacy-inventory.md)「最终状态」）；下面的事都需要账号权限、真实主机或你自己的决定，自动化做不了。

## 1. 许可证（已决定：AGPL-3.0-only）

- [x] 用户决定采用 **AGPL-3.0-only**，`LICENSE` 已是 GNU AGPL-3.0 官方全文；`web/package.json` 的 `license` 与 README 写明 `AGPL-3.0-only`。不加逐文件许可头。
- 理由：网络服务 copyleft——别人修改后把面板作为服务提供给他人，也必须公开修改后的源码；与随镜像下发的 GPL-3.0 SmartDNS 兼容；自托管代理面板类项目常用。
- 第三方兼容性评估见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)「与 AGPL-3.0-only 的兼容性」：未发现不兼容组件。
- 在第一次公开推送之前仍可改（例如改为 MIT 或 Apache-2.0）：替换 `LICENSE`，同步 README、`web/package.json`、`THIRD_PARTY_NOTICES.md`。
- [ ] 若公开仓库放在组织下，决定是否把 Go 模块路径 `github.com/radowitz/meridian` 改成新路径（要改 `go.mod` 和全部 import，单独一次提交）。

## 2. 重建公开仓库，推送单个全新提交

本地历史里有作者个人邮箱（113 个提交的作者/提交者字段）和清理之前的私人拓扑、网段、节点名（见 [privacy-inventory.md](privacy-inventory.md) F 节）。**不要推送现有历史。**

- [ ] 在 GitHub 上删除旧的公开仓库；确认没有残留的 fork、PR 引用、Release 附件和 GHCR 包（这些不在本地，无法从这里检查）。
- [ ] 决定 `docs/privacy-inventory.md`、`docs/review-391aa50.md`、`docs/evidence/` 是否随公开仓库发布。前者是开源前的内部记录，**建议不发布**（它描述了清理过的类型和映射）；evidence 已标为历史 / 已脱敏。
- [ ] 从清理完的工作区导出一份不带历史的树，例如：

  ```sh
  git init meridian-public && cd meridian-public
  # 复制工作区文件（排除 .git、.gocache、.concord-local-cache、web/node_modules、web/dist）
  git -c user.name="<公开署名>" -c user.email="<id>+<user>@users.noreply.github.com" commit -m "Initial public release"
  ```

- [ ] 推送前在新目录里再跑一次 [privacy-inventory.md](privacy-inventory.md)「最终 grep」里的命令，结果应与那里记录的一致。
- [ ] 确认 `git log --format='%an %ae %cn %ce'` 只有 noreply 地址。
- [ ] 私有仓库保留完整历史。

## 3. GitHub 设置

- [ ] Settings → Actions → General → Workflow permissions：允许 `release-images.yml` 需要的 `contents: write`、`packages: write`（工作流里已按 job 声明，仓库级默认可保持只读）。
- [ ] 确认 `ci.yml` 在新仓库的第一次推送上通过。
- [ ] GHCR：第一次推送后在 Packages 里把 `meridian` 包设为 Public，并关联到仓库。镜像名是 `ghcr.io/<仓库所有者小写>/meridian`；`install.sh` / `upgrade.sh` 用 `MERIDIAN_IMAGE_OWNER` 或 `MERIDIAN_IMAGE_REPO` 指向它。

## 4. 第一次发布

- [ ] 履行第三方许可（[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)「兼容性要点」）：
  - [ ] 把 SmartDNS Release48.4 的源码包作为 Release 附件上传（或在 Release 说明里给出书面源码提供），附 GPL-3.0 全文；
  - [ ] 让镜像带上 wstunnel（BSD-3-Clause）、gost（MIT）、SmartDNS（GPL-3.0）的许可全文和 `THIRD_PARTY_NOTICES.md`（建议放 `/usr/share/meridian/licenses/`，**尚未实现**）；
  - [ ] 核对 chnroute 数据源 `gaoyifan/china-operator-ip` 的许可（标为待确认）。
- [ ] Actions → Release images → Run workflow：先不勾 `publish` 跑一次，确认两种架构都能构建；再勾 `publish` 推送 `ghcr.io/<owner>/meridian:<版本>` 并生成 Release 草稿。
- [ ] 检查 Release 草稿（附件里 SmartDNS 镜像摘要文件等），补发布说明后发布。
- [ ] 把 README 和 `docs/user/quickstart.md` 里「还没有发布预构建镜像」「用 `--build`」改成 `--version <版本>`。
- [ ] 在一台干净的 Debian 13 上用发布的镜像走一遍快速上手。

## 5. 没有在真实主机上验证过的部分

以下只跑过自动化回归（离线桩、单元测试、golden），发布说明里应如实写明，或先在真实主机上验证：

- [ ] `install.sh` 在全新 Debian 13 上的完整运行（含 Docker 安装、镜像拉取 / 构建、`meridian-host`、健康检查）。
- [ ] 管理防火墙 `inet meridian_mgmt` 在真实 Debian 上加载、开机先于 Docker、只放行局域网和 `--allow` 来源、Docker DNAT 的端口也被约束。
- [ ] `upgrade.sh` 的升级与失败自动恢复，`rollback.sh` 的成对回滚和 `pre-rollback` 备份。
- [ ] `release-images.yml` 的一次真实运行（构建、推送、Release 草稿）。
- [ ] 首次配置向导 + 四种模板在真实服务器上部署；直连出口在真实网络上的分流、防泄露、地区组切换和 `/v1/groups/state` 状态读回。
- [ ] 单中继、备用中继组到达的备用枢纽、IX 专线主枢纽在真实网络上的切换。
- [ ] 网络命名空间测试（`MERIDIAN_NETNS_TEST=1`，需要 Linux root）在当前版本上重跑；`docs/evidence/` 里的记录都对应旧版本。
- [ ] 面板下发的二进制在真实主机上的传送、核对和激活；远端预检、补偿、撤回。
- [ ] 真实设备上的泄漏签收（抓包、断隧道、DNS 泄漏测试、手机 IPv6），见 [verification.md](verification.md)。

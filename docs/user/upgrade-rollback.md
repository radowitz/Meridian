# 升级与回滚

首次安装见 [quickstart.md](quickstart.md) 和 [install.md](install.md)。升级和回滚只换面板镜像、宿主 `meridian` 二进制和数据卷，不动正在运行的数据面。

## 升级

```sh
sudo bash deploy/debian/upgrade.sh v1.5.0              # 拉取 ghcr.io/<owner>/meridian:v1.5.0
sudo bash deploy/debian/upgrade.sh --image <镜像名>
sudo bash deploy/debian/upgrade.sh --image-tar meridian.tar.gz
#   --keep N              保留最近 N 份备份（默认 5）
#   --health-timeout S    健康检查等待秒数（默认 90）
```

过程：

1. 记录正在运行的镜像（ID 与名称）；`deploy/.env` 缺少 `MERIDIAN_BIND` 时从现有容器补上，地址不变。
2. 拉取或载入新镜像，核对架构。拉取失败时什么都不改。新旧镜像相同则直接结束。
3. 停止面板容器（停止写入），把数据卷和凭据卷、`deploy/.env`、宿主 `meridian` 二进制备份到 `/var/lib/meridian-backups/<编号>/`（目录 0700，带 `SHA256SUMS`），旧镜像打上 `meridian-rollback:<编号>` 标签以免被清理。
4. 换上新的宿主二进制并重启 `meridian-host`，用新镜像重建面板容器。
5. 检查容器运行且 `/api/health` 应答。**失败即自动恢复**：卷、`.env`、二进制和旧镜像一起回到第 3 步的状态，退出码 1。
6. 成功后只保留最近 N 份备份。

数据面（`meridian.service`）在整个过程中不停。unit 文件、sysctl 和管理防火墙归 `install.sh` 管，`upgrade.sh` 不安装也不改它们。

**本版需要重跑一次 `install.sh`。** 管理防火墙（`inet meridian_mgmt`，局域网网卡和来源网段同时匹配，见 [install.md](install.md#管理防火墙)）只由 `install.sh` 安装。已有部署只跑 `upgrade.sh` 得不到它。升级到本版后在网关上执行一次：

```sh
sudo bash deploy/debian/install.sh        # 沿用 deploy/.env 里的镜像和地址；不重新生成任何凭据
sudo nft list table inet meridian_mgmt    # 确认已加载
```

以后某个版本的说明再要求时，同样重跑一次。

`install.sh`、`upgrade.sh`、`rollback.sh` 共用一把锁（`/run/meridian-upgrade.lock`），同一时间只能运行一个；本机没有 `flock`（util-linux）时三个脚本都拒绝运行。

备份里有全部服务器的 SSH 凭据和私钥，按私钥对待。

## 回滚

```sh
sudo bash deploy/debian/rollback.sh --list             # 列出备份
sudo bash deploy/debian/rollback.sh                    # 回到最新一份备份（会确认）
sudo bash deploy/debian/rollback.sh 20261118T010203Z --yes
```

回滚把一份备份**成对**恢复：备份时的卷内容加上写下这些数据的镜像。备份之后在面板里做的修改会丢失，所以回滚前先把当前状态另存为一份 `pre-rollback` 备份，回滚本身也能撤回。以下情况拒绝回滚：

- 备份文件与 `SHA256SUMS` 不符；
- 本机已经没有 `meridian-rollback:<编号>` 镜像，或架构不符。

恢复卷分两步：先把两个卷的备份都解包到各自卷里的临时目录，两份都成功后再整体替换。任一份解包失败，两个卷都保持原样。恢复后要求 `meridian-host` 重启成功并建立控制套接字；连 `systemctl list-unit-files meridian-host.service` 都失败时，按恢复失败处理，不报成功。

不支持把旧镜像直接跑在新数据上（任意降级）。

## 在网关上调用 API

```sh
sudo bash deploy/debian/api.sh GET /api/meta
sudo bash deploy/debian/api.sh POST /api/validate < topology.json
```

面板口令在容器内读取，不会打印、不复制到宿主，也不出现在任何进程的命令行里（宿主的 `docker exec` 和容器里的 `curl` 都没有）：容器内的 shell 用内建命令把 `Authorization` 首部写进一个新建的 0600 临时 curl 配置文件，`curl -K` 从文件读取，调用结束即删除。路径必须以 `/api/` 开头，不能含 `.` 或 `..` 段（包括 `%2e` 编码形式和编码的斜杠）。

## 本地验证

脚本的参数、重复执行和失败恢复由 `internal/deployscripts` 的离线测试覆盖（用桩代替 docker/systemctl/curl，不连真实 Docker）。这只是代码回归，不等于在真实网关上的验证。

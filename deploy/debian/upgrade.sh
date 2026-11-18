#!/bin/bash
# Upgrade the Meridian panel (container image + host agent binary) in one
# command, with a backup and automatic rollback.
#
#   sudo bash deploy/debian/upgrade.sh <version>        e.g. v1.4.0
#   sudo bash deploy/debian/upgrade.sh --image <ref>
#   sudo bash deploy/debian/upgrade.sh --image-tar <file>
#     --keep N             backups to keep (default 5)        MERIDIAN_BACKUP_KEEP
#     --health-timeout S   seconds to wait for /api/health (default 90)
#
# Steps: record the running image (ID and reference) -> obtain the new image
# (pull / load; architecture checked) -> stop the panel (no writes) -> back
# up the data and secrets volumes, deploy/.env and the host binary to
# /var/lib/meridian-backups/<id>/ (0700, SHA256SUMS) and tag the old image
# meridian-rollback:<id> -> install the new host binary, restart
# meridian-host -> recreate the panel on the new image -> health check.
# Any failure after the backup restores it (volumes, .env, binary, image)
# and exits 1. The data plane (meridian.service) is never stopped.
#
# Unit files, sysctls and the firewall are owned by install.sh: when a
# release changes them its notes say to re-run install.sh as well.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/debian/lib.sh
. "${here}/lib.sh"

usage() { sed -n '/^#   sudo/,/^#     --health/p' "$0" | sed 's/^# \{0,1\}//'; }

target_ref=""
tar_file=""
keep="${MERIDIAN_BACKUP_KEEP:-5}"
timeout="${MERIDIAN_HEALTH_TIMEOUT:-90}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) [[ $# -ge 2 ]] || usage_die "--image 需要一个值"; target_ref="$2"; shift 2 ;;
    --image-tar) [[ $# -ge 2 ]] || usage_die "--image-tar 需要一个值"; tar_file="$2"; shift 2 ;;
    --keep) [[ $# -ge 2 ]] || usage_die "--keep 需要一个值"; keep="$2"; shift 2 ;;
    --health-timeout) [[ $# -ge 2 ]] || usage_die "--health-timeout 需要一个值"; timeout="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage_die "未知参数：$1" ;;
    *)
      [[ -z "${target_ref}" ]] || usage_die "只能给一个版本。"
      valid_version "$1" || usage_die "版本应形如 v1.2.3：$1"
      target_ref="$(default_image_repo):$1"
      shift ;;
  esac
done
[[ -n "${target_ref}" || -n "${tar_file}" ]] || { usage >&2; exit 2; }
[[ -z "${target_ref}" || -z "${tar_file}" ]] || usage_die "版本/--image 与 --image-tar 只能选一个。"
[[ -z "${target_ref}" ]] || valid_image_ref "${target_ref}" || usage_die "不是合法的镜像名：${target_ref}"
[[ "${keep}" =~ ^[1-9][0-9]*$ ]] || usage_die "--keep 必须是正整数。"
[[ "${timeout}" =~ ^[1-9][0-9]*$ ]] || usage_die "--health-timeout 必须是正整数（秒）。"

require_root deploy/debian/upgrade.sh

repo="$(cd "${here}/../.." && pwd)"
envfile="${MERIDIAN_ENV_FILE:-${repo}/deploy/.env}"
compose_init "${repo}/deploy/docker-compose.yml"

# One install, upgrade or rollback at a time (same lock as install.sh).
acquire_lock

old_cid="$(panel_container)"
[[ -n "${old_cid}" ]] || die "没有找到面板容器。首次安装请用 deploy/debian/install.sh。"
old_image_id="$("${DOCKER}" inspect --format '{{.Image}}' "${old_cid}")"
old_ref="$(env_get MERIDIAN_IMAGE "${envfile}")"
[[ -n "${old_ref}" ]] || old_ref="$("${DOCKER}" inspect --format '{{.Config.Image}}' "${old_cid}")"
echo "当前面板镜像：${old_ref}（${old_image_id}）"

# Keep the address: an older deploy/.env may not name MERIDIAN_BIND while
# the container (or the stored panel_bind) does.
if [[ -z "$(env_get MERIDIAN_BIND "${envfile}")" ]]; then
  b="$(container_env "${old_cid}" MERIDIAN_BIND)"
  if [[ -n "${b}" ]]; then
    env_set MERIDIAN_BIND "${b}" "${envfile}"
    echo "沿用面板监听地址 ${b}（写入 deploy/.env）。"
  fi
fi

if [[ -n "${tar_file}" ]]; then
  target_ref="$(load_image_tar "${tar_file}")"
else
  pull_image "${target_ref}"
fi
check_image_arch "${target_ref}"
new_image_id="$("${DOCKER}" image inspect --format '{{.Id}}' "${target_ref}")"
if [[ "${new_image_id}" == "${old_image_id}" ]]; then
  env_set MERIDIAN_IMAGE "${target_ref}" "${envfile}"
  echo "面板已经运行这个镜像（${new_image_id}），无需升级。"
  exit 0
fi

# MERIDIAN_BACKUP_ID: fixed id for the offline tests only.
id="${MERIDIAN_BACKUP_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ ! -e "$(backup_root)/${id}" ]] || id="${id}-$$"
echo "停止面板（停止写入）并备份……"
"${COMPOSE[@]}" stop meridian
if ! (make_backup "${id}" "${old_cid}" "${old_image_id}" "${old_ref}" "${envfile}" upgrade); then
  rm -rf "$(backup_root)/${id:?}"
  "${COMPOSE[@]}" start meridian || true
  die "备份失败，未做任何升级，面板已按原样启动。"
fi
bdir="$(backup_root)/${id}"

recover() {
  trap - ERR
  set +e
  echo "升级失败：$1。恢复备份 ${id}……" >&2
  "${COMPOSE[@]}" stop meridian
  local restored=1
  ( restore_backup "${bdir}" "${old_cid}" "${envfile}" ) || restored=0
  "${COMPOSE[@]}" up -d --no-build meridian
  local cid
  cid="$(panel_container)"
  local hint
  hint="$(sed -n 's/^PANEL_BIND=//p' "${bdir}/meta.env")"
  [[ -n "${hint}" ]] || hint="$(env_get MERIDIAN_BIND "${envfile}")"
  if [[ "${restored}" != 1 ]]; then
    echo "恢复备份 ${id} 没有完成（输出见上），没有回到升级前的版本。备份保留在 ${bdir}；修好原因后执行 deploy/debian/rollback.sh ${id}。" >&2
  elif [[ -n "${cid}" ]] && health_wait "${cid}" "${timeout}" "${hint}"; then
    echo "已回到升级前的版本（${old_ref}），数据为升级前的备份。" >&2
  else
    echo "恢复后面板仍未通过健康检查。备份保留在 ${bdir}；可再执行 deploy/debian/rollback.sh ${id}。" >&2
  fi
  exit 1
}
trap 'recover "命令失败（upgrade.sh 第 ${LINENO} 行）"' ERR

install_host_bin "${target_ref}" || recover "新版 meridian-host 没有启动（journalctl -u meridian-host）"
env_set MERIDIAN_IMAGE "${target_ref}" "${envfile}"
"${COMPOSE[@]}" up -d --no-build meridian
new_cid="$(panel_container)"
health_wait "${new_cid}" "${timeout}" || recover "新版面板没有通过健康检查"
trap - ERR

prune_backups "${keep}"
echo "升级完成：${old_ref} -> ${target_ref}。备份 ${id}（回滚：sudo bash deploy/debian/rollback.sh）。"

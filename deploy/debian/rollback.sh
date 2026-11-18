#!/bin/bash
# Roll the Meridian panel back to a backup made by upgrade.sh.
#
#   sudo bash deploy/debian/rollback.sh [--list] [<backup-id>] [--yes]
#     <backup-id>          default: the newest backup
#     --list               list backups and exit
#     --yes                do not ask (required without a terminal)
#     --health-timeout S   seconds to wait for /api/health (default 90)
#
# A backup is restored as a pair: the volumes as they were when it was taken
# AND the image that wrote them (tag meridian-rollback:<id>). Changes made in
# the panel after that backup are lost; the current state is backed up first
# (kind pre-rollback) so this step can itself be undone. A backup whose
# files do not match SHA256SUMS, or whose image is no longer on this host,
# is refused: there is no promise of running an older image on newer data.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/debian/lib.sh
. "${here}/lib.sh"

usage() { sed -n '/^#   sudo/,/^#     --health/p' "$0" | sed 's/^# \{0,1\}//'; }

want=""
list=0
yes=0
timeout="${MERIDIAN_HEALTH_TIMEOUT:-90}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --list) list=1; shift ;;
    --yes|-y) yes=1; shift ;;
    --health-timeout) [[ $# -ge 2 ]] || usage_die "--health-timeout 需要一个值"; timeout="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage_die "未知参数：$1" ;;
    *)
      [[ -z "${want}" ]] || usage_die "只能给一个备份。"
      [[ "$1" =~ ^[0-9]{8}T[0-9]{6}Z(-[0-9]+)?$ ]] || usage_die "备份编号形如 20261118T010203Z：$1"
      want="$1"; shift ;;
  esac
done
[[ "${timeout}" =~ ^[1-9][0-9]*$ ]] || usage_die "--health-timeout 必须是正整数（秒）。"

require_root deploy/debian/rollback.sh

root="$(backup_root)"
if [[ "${list}" == 1 ]]; then
  [[ -d "${root}" ]] || { echo "没有备份。"; exit 0; }
  for d in $(ls -1 "${root}" | sort -r); do
    [[ -f "${root}/${d}/meta.env" ]] || continue
    printf '%s  %s  %s\n' "${d}" "$(sed -n 's/^KIND=//p' "${root}/${d}/meta.env")" "$(sed -n 's/^IMAGE_REF=//p' "${root}/${d}/meta.env")"
  done
  exit 0
fi

# One install, upgrade or rollback at a time (same lock as install.sh).
acquire_lock

[[ -n "${want}" ]] || want="$(latest_backup)"
[[ -n "${want}" ]] || die "没有可用的备份（${root}）。"
bdir="${root}/${want}"
[[ -d "${bdir}" ]] || die "没有备份 ${want}。"
verify_backup "${bdir}"
"${DOCKER}" image inspect "meridian-rollback:${want}" >/dev/null 2>&1 \
  || die "本机没有备份 ${want} 对应的镜像 meridian-rollback:${want}，不能回滚到它（数据与镜像必须成对恢复）。"
check_image_arch "meridian-rollback:${want}"
target_ref="$(sed -n 's/^IMAGE_REF=//p' "${bdir}/meta.env")"

if [[ "${yes}" != 1 ]]; then
  if [[ ! -t 0 ]]; then
    die "回滚会丢弃备份 ${want} 之后在面板里做的修改。确认后加 --yes 再运行。"
  fi
  read -r -p "回滚到备份 ${want}（${target_ref}）？此后在面板里的修改会丢失。[y/N] " ans || ans=""
  [[ "${ans}" == y || "${ans}" == Y ]] || { echo "已取消。"; exit 1; }
fi

repo="$(cd "${here}/../.." && pwd)"
envfile="${MERIDIAN_ENV_FILE:-${repo}/deploy/.env}"
compose_init "${repo}/deploy/docker-compose.yml"


cid="$(panel_container)"
[[ -n "${cid}" ]] || die "没有找到面板容器。"
cur_image_id="$("${DOCKER}" inspect --format '{{.Image}}' "${cid}")"
cur_ref="$(env_get MERIDIAN_IMAGE "${envfile}")"

"${COMPOSE[@]}" stop meridian
safety="${MERIDIAN_BACKUP_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ ! -e "${root}/${safety}" && "${safety}" != "${want}" ]] || safety="${safety}-$$"
if ! (make_backup "${safety}" "${cid}" "${cur_image_id}" "${cur_ref}" "${envfile}" pre-rollback); then
  rm -rf "${root:?}/${safety}"
  "${COMPOSE[@]}" start meridian || true
  die "无法先备份当前状态，未回滚。"
fi

( restore_backup "${bdir}" "${cid}" "${envfile}" ) || die "恢复失败。当前状态已备份为 ${safety}：sudo bash deploy/debian/rollback.sh ${safety}"
"${COMPOSE[@]}" up -d --no-build meridian
new_cid="$(panel_container)"
# The pre-rollback image may predate "meridian panel-bind": check the bind
# saved with the backup (else the restored deploy/.env).
saved_bind="$(sed -n 's/^PANEL_BIND=//p' "${bdir}/meta.env")"
[[ -n "${saved_bind}" ]] || saved_bind="$(env_get MERIDIAN_BIND "${envfile}")"
if ! health_wait "${new_cid}" "${timeout}" "${saved_bind}"; then
  die "回滚后面板没有通过健康检查。回滚前的状态在备份 ${safety}：sudo bash deploy/debian/rollback.sh ${safety} --yes"
fi
echo "已回滚到备份 ${want}（${target_ref}）。回滚前的状态保存为备份 ${safety}。"

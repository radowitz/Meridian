# shellcheck shell=bash
# Shared helpers for install.sh, upgrade.sh, rollback.sh and api.sh.
# Sourced, never run. Every external command goes through a variable so the
# offline tests (internal/deployscripts) can run the scripts against stubs:
#   MERIDIAN_DOCKER, MERIDIAN_SYSTEMCTL, MERIDIAN_CURL, MERIDIAN_NFT, MERIDIAN_FLOCK
# and every host path the upgrade/rollback flow writes can be moved:
#   MERIDIAN_BACKUP_DIR, MERIDIAN_HOST_BIN, MERIDIAN_ENV_FILE.
# MERIDIAN_TEST_MODE=1 skips the root check (tests only; the stubs never
# touch the host).

DOCKER="${MERIDIAN_DOCKER:-docker}"
SYSTEMCTL="${MERIDIAN_SYSTEMCTL:-systemctl}"
CURL="${MERIDIAN_CURL:-curl}"
NFT="${MERIDIAN_NFT:-nft}"
FLOCK="${MERIDIAN_FLOCK:-flock}"

# Image naming. Nothing is assumed to be published: a pull that fails says
# so and names the local build instead.
MERIDIAN_IMAGE_OWNER_DEFAULT="radowitz"
default_image_repo() {
  echo "${MERIDIAN_IMAGE_REPO:-ghcr.io/${MERIDIAN_IMAGE_OWNER:-${MERIDIAN_IMAGE_OWNER_DEFAULT}}/meridian}"
}

die() { echo "错误：$*" >&2; exit 1; }
usage_die() { echo "$*" >&2; exit 2; }

require_root() {
  if [[ "${MERIDIAN_TEST_MODE:-}" == 1 ]]; then
    return 0
  fi
  if [[ "${EUID}" -ne 0 ]]; then
    die "请用 root 运行：sudo bash $1"
  fi
}

# acquire_lock: one install, upgrade or rollback at a time. All three
# scripts take the same lock (MERIDIAN_LOCK_FILE, held on fd 9 until the
# script exits). Without flock(1) the script refuses to continue rather than
# run unlocked.
acquire_lock() {
  local lock="${MERIDIAN_LOCK_FILE:-/run/meridian-upgrade.lock}"
  command -v "${FLOCK}" >/dev/null 2>&1 \
    || die "没有找到 flock（util-linux 软件包），无法保证安装、升级、回滚不会同时进行，拒绝继续。请先 apt-get install util-linux。"
  exec 9>"${lock}" || die "无法打开锁文件 ${lock}。"
  "${FLOCK}" -n 9 || die "另一个安装、升级或回滚正在进行（${lock}）。"
}

# valid_version: a release tag such as v1.4.0, 1.4.0 or 1.4.0-rc.1.
valid_version() {
  [[ "$1" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]]
}

# valid_image_ref: [registry/]name[:tag][@sha256:...], no spaces or shell
# metacharacters (the value is written to deploy/.env).
valid_image_ref() {
  [[ "$1" =~ ^[a-z0-9][a-z0-9._/-]*(:[0-9]+)?[a-z0-9._/-]*(:[A-Za-z0-9_.-]{1,128})?(@sha256:[0-9a-f]{64})?$ ]]
}

valid_ipv4() {
  local ip="$1" o
  [[ "${ip}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r -a o <<<"${ip}"
  for x in "${o[@]}"; do
    (( 10#${x} <= 255 )) || return 1
  done
  [[ "${ip}" != 0.0.0.0 ]]
}

# api_path_has_dot_segment PATH: PATH (query included) has a "." or ".."
# segment, literal or percent-encoded in any case (%2e, %2E), in the path
# or the query.
api_path_has_dot_segment() {
  local p
  p="$(printf '%s' "$1" | sed 's/%2[eE]/./g')"
  [[ "/${p}/" == *"/./"* || "/${p}/" == *"/../"* ]] && return 0
  # Encoded slashes would hide a segment from the check above.
  [[ "$1" == *%2[fF]* || "$1" == *%5[cC]* ]]
}

valid_ifname() { [[ "$1" =~ ^[A-Za-z0-9_.@-]{1,15}$ ]]; }

# valid_cidr: IPv4 or IPv6 prefix for the management allow list.
valid_cidr() {
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ || "$1" =~ ^[0-9A-Fa-f:]+/[0-9]{1,3}$ ]]
}

# env_get KEY FILE: value of KEY= in FILE (last one wins), empty if absent.
env_get() {
  local key="$1" file="$2"
  [[ -f "${file}" ]] || return 0
  sed -n "s/^${key}=//p" "${file}" | tail -n1
}

# env_set KEY VALUE FILE: replace or append KEY=VALUE, keep every other
# line, write atomically and leave the file 0600. Running it twice with the
# same value leaves the file byte-identical.
env_set() {
  local key="$1" val="$2" file="$3" tmp
  tmp="$(mktemp "${file}.XXXXXX")"
  chmod 0600 "${tmp}"
  if [[ -f "${file}" ]]; then
    grep -v "^${key}=" "${file}" > "${tmp}" || true
  fi
  printf '%s=%s\n' "${key}" "${val}" >> "${tmp}"
  mv -f "${tmp}" "${file}"
  chmod 0600 "${file}"
}

env_unset() {
  local key="$1" file="$2" tmp
  [[ -f "${file}" ]] || return 0
  tmp="$(mktemp "${file}.XXXXXX")"
  chmod 0600 "${tmp}"
  grep -v "^${key}=" "${file}" > "${tmp}" || true
  mv -f "${tmp}" "${file}"
  chmod 0600 "${file}"
}

# compose_cmd: fills the array COMPOSE with the compose invocation for FILE.
compose_init() {
  local file="$1"
  if "${DOCKER}" compose version >/dev/null 2>&1; then
    COMPOSE=("${DOCKER}" compose -f "${file}")
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose -f "${file}")
  else
    die "没有找到 docker compose。"
  fi
  # deploy/.env is next to the compose file; compose reads it from there.
}

# panel_container: id of the running (or stopped) panel container, empty if none.
panel_container() {
  "${COMPOSE[@]}" ps -a -q meridian 2>/dev/null | head -n1
}

# container_env CID KEY: KEY from the container's environment.
container_env() {
  "${DOCKER}" inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$1" 2>/dev/null \
    | sed -n "s/^$2=//p" | head -n1
}

host_arch() {
  case "$(uname -m)" in
    x86_64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) uname -m ;;
  esac
}

# check_image_arch REF: the image must match this host.
check_image_arch() {
  local ref="$1" a h
  a="$("${DOCKER}" image inspect --format '{{.Architecture}}' "${ref}" 2>/dev/null)" || die "本地没有镜像 ${ref}"
  h="${MERIDIAN_HOST_ARCH:-$(host_arch)}"
  if [[ "${a}" != "${h}" ]]; then
    die "镜像 ${ref} 的架构是 ${a}，本机是 ${h}。请换用对应架构的镜像，或用 --platform linux/${h} 重新构建。"
  fi
}

# pull_image REF: pull, or fail with what to do instead. Never claims the
# image exists upstream.
pull_image() {
  local ref="$1"
  if "${DOCKER}" image inspect "${ref}" >/dev/null 2>&1 && [[ "${ref}" == *@sha256:* ]]; then
    return 0
  fi
  if ! "${DOCKER}" pull "${ref}"; then
    cat >&2 <<EOF
错误：拉取镜像 ${ref} 失败。
  可能原因：该版本尚未发布到这个仓库、仓库是私有的，或本机访问不到镜像仓库。
  本仓库只提供构建工作流定义（.github/workflows/release-images.yml），不保证任何版本已经发布。
  可选办法：
    - 在本机从源码构建：       sudo bash deploy/debian/install.sh --build
    - 在能联网的机器上构建并导出（docker save），再用：
                               sudo bash deploy/debian/install.sh --image-tar <文件>
    - 改用其他仓库：           MERIDIAN_IMAGE_OWNER=<所有者> 或 --image <完整镜像名>
EOF
    exit 1
  fi
}

# load_image_tar FILE: load a docker save archive and print the panel image
# reference it contains. An archive may carry other images too (the docs'
# "docker save meridian:local pymumu/smartdns" puts SmartDNS beside the
# panel, and docker load lists them in no fixed order), so the panel image
# is the one whose name says meridian; failing that, the only image loaded;
# otherwise meridian:local. Never a SmartDNS image.
load_image_tar() {
  local f="$1" out refs ref
  [[ -r "${f}" ]] || die "镜像包读不到：${f}"
  out="$("${DOCKER}" load -i "${f}")" || die "docker load 失败：${f}"
  echo "${out}" >&2
  refs="$(sed -n 's/^Loaded image: //p' <<<"${out}")"
  ref="$(grep -E '(^|/)meridian(:|@|$)' <<<"${refs}" | head -n1 || true)"
  if [[ -z "${ref}" ]]; then
    local others
    others="$(grep -viE 'smartdns' <<<"${refs}" || true)"
    if [[ -n "${others}" && "$(wc -l <<<"${others}")" -eq 1 ]]; then
      ref="${others}"
    fi
  fi
  [[ -n "${ref}" ]] || ref="meridian:local"
  echo "${ref}"
}

# panel_supports_bind CID: the container's meridian CLI has the panel-bind
# subcommand. Images from before it fall through to serving the panel on
# an unknown subcommand, so it is detected from the binary instead of by
# running it (bounded; never starts a panel).
panel_supports_bind() {
  local to=()
  command -v timeout >/dev/null 2>&1 && to=(timeout 10)
  "${to[@]}" "${DOCKER}" exec "$1" grep -qa -- panel-bind /usr/local/bin/meridian >/dev/null 2>&1
}

# panel_bind_of CID [HINT]: the address the running panel listens on. In
# order: the container's MERIDIAN_BIND, HINT (the bind saved with a backup
# or in deploy/.env), the panel's own answer (panel-bind, only when the
# image has it), else 127.0.0.1:8787.
panel_bind_of() {
  local b to=()
  b="$(container_env "$1" MERIDIAN_BIND)"
  [[ -n "${b}" ]] || b="${2:-}"
  if [[ -z "${b}" ]] && panel_supports_bind "$1"; then
    command -v timeout >/dev/null 2>&1 && to=(timeout 10)
    b="$("${to[@]}" "${DOCKER}" exec "$1" meridian panel-bind 2>/dev/null | tail -n1)"
  fi
  echo "${b:-127.0.0.1:8787}"
}

# health_wait CID TIMEOUT [BIND_HINT]: container running and /api/health
# answers (BIND_HINT: see panel_bind_of).
health_wait() {
  local cid="$1" timeout="$2" hint="${3:-}" waited=0 bind state
  while (( waited < timeout )); do
    state="$("${DOCKER}" inspect --format '{{.State.Status}}' "${cid}" 2>/dev/null || true)"
    if [[ "${state}" == running ]]; then
      bind="$(panel_bind_of "${cid}" "${hint}")"
      if [[ -n "${bind}" ]] && "${CURL}" -fsS --max-time 3 "http://${bind}/api/health" >/dev/null 2>&1; then
        echo "健康检查通过：http://${bind}/api/health"
        return 0
      fi
    fi
    sleep "${MERIDIAN_HEALTH_INTERVAL:-2}"
    waited=$(( waited + ${MERIDIAN_HEALTH_INTERVAL:-2} ))
  done
  echo "健康检查失败：${timeout}s 内容器状态=${state:-未知}，/api/health 未应答。" >&2
  return 1
}

# smartdns_ensure: the resolver container of the compose "dns" profile
# (meridian-smartdns, the fixed name meridian-host restarts). Needs
# compose_init.
#   - A host smartdns.service (e.g. the distribution package) takes
#     precedence: meridian-host restarts that unit, not the container
#     (internal/hostexec dnsProvider), so no container is created or started.
#   - A running container is left exactly as it is.
#   - An existing but stopped container is started and checked when
#     /etc/smartdns/smartdns.conf is there; without a config it stays
#     stopped (the first "安装到本机" writes the config and starts it).
#   - No container: created; started and checked at once when the config is
#     there, else only created and started by the first "安装到本机".
smartdns_ensure() {
  local conf="${MERIDIAN_SMARTDNS_CONF:-/etc/smartdns/smartdns.conf}" name=meridian-smartdns state=""
  if "${SYSTEMCTL}" cat smartdns.service >/dev/null 2>&1; then
    echo "本机已有 smartdns.service：meridian-host 重启的是这个宿主单元，不创建也不启动容器 ${name}。"
    return 0
  fi
  if "${DOCKER}" inspect --type container "${name}" >/dev/null 2>&1; then
    state="$("${DOCKER}" inspect --type container --format '{{.State.Status}}' "${name}" 2>/dev/null || true)"
    if [[ "${state}" == running ]]; then
      echo "SmartDNS 容器 ${name} 已在运行，保持原状。"
      return 0
    fi
    if [[ ! -f "${conf}" ]]; then
      echo "SmartDNS 容器 ${name} 已存在但未运行（状态=${state:-未知}），还没有配置：面板「安装到本机」写好配置后由 meridian-host 启动。"
      return 0
    fi
    "${DOCKER}" start "${name}" >/dev/null \
      || { echo "无法启动已有的 SmartDNS 容器 ${name}：docker logs ${name}" >&2; return 1; }
    smartdns_wait_running
    return
  fi
  if [[ ! -f "${conf}" ]]; then
    "${COMPOSE[@]}" --profile dns create --no-recreate smartdns \
      || { echo "无法创建 SmartDNS 容器（${COMPOSE[*]} --profile dns create smartdns）。" >&2; return 1; }
    echo "已创建 SmartDNS 容器 ${name}；面板「安装到本机」写好配置后由 meridian-host 启动并检查应答。"
    return 0
  fi
  "${COMPOSE[@]}" --profile dns up -d --no-recreate smartdns \
    || { echo "无法启动 SmartDNS 容器（${COMPOSE[*]} --profile dns up -d smartdns）。" >&2; return 1; }
  smartdns_wait_running
}

smartdns_wait_running() {
  local name=meridian-smartdns timeout="${MERIDIAN_SMARTDNS_TIMEOUT:-30}" waited=0 state=""
  while (( waited < timeout )); do
    state="$("${DOCKER}" inspect --type container --format '{{.State.Status}}' "${name}" 2>/dev/null || true)"
    if [[ "${state}" == running ]]; then
      echo "SmartDNS 容器 ${name} 已启动。"
      return 0
    fi
    sleep "${MERIDIAN_HEALTH_INTERVAL:-2}"
    waited=$(( waited + ${MERIDIAN_HEALTH_INTERVAL:-2} ))
  done
  echo "SmartDNS 容器 ${name} 没有运行（状态=${state:-未知}）：docker logs ${name}" >&2
  return 1
}

# lan_sources IF: the source prefixes of the LAN on IF, comma-separated:
# the IPv4 and IPv6 networks connected to IF (kernel routes: its LAN
# address/prefix, IPv6 global prefix or ULA) and fe80::/10. Empty IF or an
# interface with no address gives only fe80::/10 (with IF unset there is no
# LAN rule at all).
lan_sources() {
  local ifn="$1" out=() p
  [[ -n "${ifn}" ]] || return 0
  while read -r p _; do
    [[ "${p}" == */* ]] && out+=("${p}")
  done < <(ip -4 route show dev "${ifn}" proto kernel scope link 2>/dev/null; ip -6 route show dev "${ifn}" proto kernel 2>/dev/null)
  local seen=" " r=()
  for p in "${out[@]+"${out[@]}"}" fe80::/10; do
    [[ "${p}" == fe80::/64 ]] && continue
    [[ "${seen}" == *" ${p} "* ]] && continue
    seen+="${p} "
    r+=("${p}")
  done
  (IFS=,; echo "${r[*]}")
}

# render_mgmt_firewall PORT LANIF LANSRC ALLOW...: an nft file owning only
# the table inet meridian_mgmt. The panel port is accepted from lo, from
# LANIF only when the source is also one of LANSRC (comma list of the LAN's
# own prefixes, see lan_sources), from the remote-access WireGuard
# interface (its peers are pinned to their pool addresses; the data-plane
# firewall allows that pool to the panel too), and from ALLOW sources on
# any interface. A connection that arrives on the LAN NIC from elsewhere -
# e.g. port-forwarded from the WAN by the upstream router on a single-NIC
# side gateway - is dropped. Loading it twice gives the same ruleset (the
# table is created, deleted and re-declared in one transaction). Base
# chains have policy accept and match only the panel port, so SSH and every
# rule of other tables stay as they were. IPv4 and IPv6 share the inet table.
render_mgmt_firewall() {
  local port="$1" lanif="$2" lansrc="$3"
  shift 3
  local v4=() v6=() l4=() l6=() ls=() c
  for c in "$@"; do
    [[ -n "${c}" ]] || continue
    if [[ "${c}" == *:* ]]; then v6+=("${c}"); else v4+=("${c}"); fi
  done
  if [[ -n "${lanif}" ]]; then
    IFS=, read -r -a ls <<<"${lansrc}"
    for c in "${ls[@]+"${ls[@]}"}"; do
      [[ -n "${c}" ]] || continue
      if [[ "${c}" == *:* ]]; then l6+=("${c}"); else l4+=("${c}"); fi
    done
  fi
  _set() { printf '  set %s {\n    type %s; flags interval;\n    elements = { %s }\n  }\n' "$1" "$2" "$(shift 2; IFS=,; echo "$*" | sed 's/,/, /g')"; }
  cat <<EOF
#!/usr/sbin/nft -f
# Meridian management firewall (written by deploy/debian/install.sh).
# Only the panel port ${port}/tcp is matched; everything else, including SSH
# and other tables, is untouched. Loaded by meridian-mgmt-firewall.service.
table inet meridian_mgmt
delete table inet meridian_mgmt
table inet meridian_mgmt {
EOF
  (( ${#l4[@]} )) && _set lan4 ipv4_addr "${l4[@]}"
  (( ${#l6[@]} )) && _set lan6 ipv6_addr "${l6[@]}"
  (( ${#v4[@]} )) && _set allow4 ipv4_addr "${v4[@]}"
  (( ${#v6[@]} )) && _set allow6 ipv6_addr "${v6[@]}"
  cat <<EOF
  chain input {
    type filter hook input priority filter - 10; policy accept;
    tcp dport ${port} iifname "lo" accept
EOF
  (( ${#l4[@]} )) && echo "    tcp dport ${port} iifname \"${lanif}\" ip saddr @lan4 accept"
  (( ${#l6[@]} )) && echo "    tcp dport ${port} iifname \"${lanif}\" ip6 saddr @lan6 accept"
  echo "    tcp dport ${port} iifname \"mra\" accept comment \"remote-access devices\""
  (( ${#v4[@]} )) && echo "    tcp dport ${port} ip saddr @allow4 accept"
  (( ${#v6[@]} )) && echo "    tcp dport ${port} ip6 saddr @allow6 accept"
  cat <<EOF
    tcp dport ${port} counter drop
  }
  # A port Docker publishes is DNATed before input and then forwarded: the
  # same sources as above, everything else dropped (covers Docker's own
  # port rules if iptables is ever re-enabled in /etc/docker/daemon.json).
  chain forward {
    type filter hook forward priority filter - 10; policy accept;
EOF
  local m="ct status dnat meta l4proto tcp ct original proto-dst ${port}"
  (( ${#l4[@]} )) && echo "    ${m} iifname \"${lanif}\" ip saddr @lan4 accept"
  (( ${#l6[@]} )) && echo "    ${m} iifname \"${lanif}\" ip6 saddr @lan6 accept"
  echo "    ${m} iifname \"mra\" accept"
  (( ${#v4[@]} )) && echo "    ${m} ip saddr @allow4 accept"
  (( ${#v6[@]} )) && echo "    ${m} ip6 saddr @allow6 accept"
  cat <<EOF
    ${m} counter drop
  }
}
EOF
}

# mgmt_firewall_install PORT LANIF LANSRC ALLOW...: render the management
# firewall, check it with "nft -c" and only then install and load it
# (meridian-mgmt-firewall.service). Returns non-zero, leaving the previously
# installed rules file and unit untouched, when the check or the load fails.
# MERIDIAN_MGMT_DIR / MERIDIAN_UNIT_DIR move the paths (tests only).
mgmt_firewall_install() {
  local dir="${MERIDIAN_MGMT_DIR:-/etc/meridian-host}" units="${MERIDIAN_UNIT_DIR:-/etc/systemd/system}"
  local here_lib
  here_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  install -d -m 0700 "${dir}"
  render_mgmt_firewall "$@" > "${dir}/mgmt-firewall.nft.new" || { rm -f "${dir}/mgmt-firewall.nft.new"; return 1; }
  chmod 0600 "${dir}/mgmt-firewall.nft.new"
  if ! "${NFT}" -c -f "${dir}/mgmt-firewall.nft.new"; then
    rm -f "${dir}/mgmt-firewall.nft.new"
    echo "管理防火墙规则没有通过 nft -c 检查，未加载。" >&2
    return 1
  fi
  mv -f "${dir}/mgmt-firewall.nft.new" "${dir}/mgmt-firewall.nft"
  install -m 644 "${here_lib}/meridian-mgmt-firewall.service" "${units}/meridian-mgmt-firewall.service"
  "${SYSTEMCTL}" daemon-reload || return 1
  "${SYSTEMCTL}" enable meridian-mgmt-firewall.service || return 1
  "${SYSTEMCTL}" restart meridian-mgmt-firewall.service || return 1
}

# --- backups ------------------------------------------------------------------

backup_root() { echo "${MERIDIAN_BACKUP_DIR:-/var/lib/meridian-backups}"; }

# latest_backup: id of the newest complete backup, empty if none.
latest_backup() {
  local root d
  root="$(backup_root)"
  [[ -d "${root}" ]] || return 0
  for d in $(ls -1 "${root}" 2>/dev/null | sort -r); do
    if [[ -f "${root}/${d}/meta.env" && -f "${root}/${d}/SHA256SUMS" ]]; then
      echo "${d}"
      return 0
    fi
  done
}

# prune_backups KEEP: delete the oldest complete backups beyond KEEP, and
# their rollback image tags. Incomplete directories (no SHA256SUMS) are
# removed too: they never finished and cannot be restored.
prune_backups() {
  local keep="$1" root n=0 d
  root="$(backup_root)"
  [[ -d "${root}" ]] || return 0
  for d in $(ls -1 "${root}" 2>/dev/null | sort -r); do
    if [[ ! -f "${root}/${d}/SHA256SUMS" ]]; then
      rm -rf "${root:?}/${d}"
      continue
    fi
    n=$(( n + 1 ))
    if (( n > keep )); then
      "${DOCKER}" image rm "meridian-rollback:${d}" >/dev/null 2>&1 || true
      rm -rf "${root:?}/${d}"
      echo "已删除旧备份 ${d}（保留最近 ${keep} 份）。"
    fi
  done
}

sha_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -c1-64
  else
    shasum -a 256 "$1" | cut -c1-64
  fi
}

# volume_of CID DEST: the named volume mounted at DEST in the container.
volume_of() {
  "${DOCKER}" inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}} {{.Destination}}{{println}}{{end}}{{end}}' "$1" 2>/dev/null \
    | awk -v d="$2" '$2==d{print $1; exit}'
}

# make_backup ID CID IMAGE_ID IMAGE_REF ENVFILE KIND: consistent backup of the
# panel's two volumes taken while the panel is stopped, plus the host
# binary, deploy/.env and the image (kept as tag meridian-rollback:ID).
# Archives are written by a throw-away container of the image being backed
# up (it has tar), with the volumes mounted read-only.
make_backup() {
  local id="$1" cid="$2" image_id="$3" image_ref="$4" envfile="$5" kind="$6"
  local dir vdata vsecrets bind
  dir="$(backup_root)/${id}"
  install -d -m 0700 "$(backup_root)" "${dir}"
  vdata="$(volume_of "${cid}" /var/lib/meridian)"
  vsecrets="$(volume_of "${cid}" /var/lib/meridian-secrets)"
  [[ -n "${vdata}" && -n "${vsecrets}" ]] || die "找不到面板的数据卷或凭据卷（docker inspect ${cid}）。"
  local v name
  for pair in "data:${vdata}" "secrets:${vsecrets}"; do
    name="${pair%%:*}"
    v="${pair#*:}"
    "${DOCKER}" run --rm --network none --entrypoint tar \
      -v "${v}:/v:ro" -v "${dir}:/b" "${image_id}" \
      -czf "/b/${name}.tar.gz" -C /v . || die "备份卷 ${v} 失败。"
  done
  if [[ -f "$(host_bin)" ]]; then
    cp -p "$(host_bin)" "${dir}/meridian.host"
  fi
  if [[ -f "${envfile}" ]]; then
    cp -p "${envfile}" "${dir}/deploy.env"
  fi
  "${DOCKER}" tag "${image_id}" "meridian-rollback:${id}" || die "无法为旧镜像打回滚标签。"
  {
    echo "KIND=${kind}"
    echo "IMAGE_ID=${image_id}"
    echo "IMAGE_REF=${image_ref}"
    echo "VOLUME_DATA=${vdata}"
    echo "VOLUME_SECRETS=${vsecrets}"
    bind="$(container_env "${cid}" MERIDIAN_BIND)"
    [[ -n "${bind}" ]] || bind="$(env_get MERIDIAN_BIND "${envfile}")"
    echo "PANEL_BIND=${bind}"
    echo "CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "${dir}/meta.env"
  (
    cd "${dir}" || exit 1
    for f in data.tar.gz secrets.tar.gz meta.env meridian.host deploy.env; do
      [[ -f "${f}" ]] && echo "$(sha_file "${f}")  ${f}"
    done
  ) > "${dir}/SHA256SUMS.tmp"
  mv "${dir}/SHA256SUMS.tmp" "${dir}/SHA256SUMS"
  chmod 0600 "${dir}"/*
  echo "已备份到 ${dir}"
}

# verify_backup DIR: every listed file present with its recorded digest.
verify_backup() {
  local dir="$1" sum f
  [[ -f "${dir}/SHA256SUMS" && -f "${dir}/meta.env" ]] || die "备份 ${dir} 不完整。"
  while read -r sum f; do
    [[ -f "${dir}/${f}" ]] || die "备份缺少 ${f}。"
    [[ "$(sha_file "${dir}/${f}")" == "${sum}" ]] || die "备份文件 ${f} 校验失败。"
  done < "${dir}/SHA256SUMS"
}

host_bin() { echo "${MERIDIAN_HOST_BIN:-/usr/local/bin/meridian}"; }

# install_host_bin IMAGE: copy the meridian binary out of IMAGE onto the host
# and restart meridian-host (the data plane, meridian.service, keeps running).
install_host_bin() {
  local image="$1" cid dest
  dest="$(host_bin)"
  cid="$("${DOCKER}" create "${image}")" || return 1
  if ! "${DOCKER}" cp "${cid}:/usr/local/bin/meridian" "${dest}.new"; then
    "${DOCKER}" rm -f "${cid}" >/dev/null 2>&1 || true
    return 1
  fi
  "${DOCKER}" rm -f "${cid}" >/dev/null 2>&1 || true
  chmod 0755 "${dest}.new"
  mv -f "${dest}.new" "${dest}"
  restart_host_agent
}

host_socket() { echo "${MERIDIAN_HOST_SOCKET:-/run/meridian-host/agent.sock}"; }

# restart_host_agent: restart meridian-host and require it healthy: the unit
# active and the agent's control socket (what the panel and "meridian
# host-restore" talk to) present within MERIDIAN_HOST_SOCKET_WAIT seconds.
restart_host_agent() {
  local i wait="${MERIDIAN_HOST_SOCKET_WAIT:-10}"
  # meridian-host.service is always installed by install.sh. A failing
  # query (no systemctl, systemd not reachable, unit missing) cannot prove
  # the host agent runs, so it is a failure, never "nothing to do".
  if ! "${SYSTEMCTL}" list-unit-files meridian-host.service >/dev/null 2>&1; then
    echo "无法确认 meridian-host.service（systemctl list-unit-files 失败）：宿主通道状态未知。" >&2
    return 1
  fi
  {
    "${SYSTEMCTL}" restart meridian-host.service || return 1
    "${SYSTEMCTL}" is-active --quiet meridian-host.service || return 1
    for ((i = 0; i < wait; i++)); do
      [[ -S "$(host_socket)" ]] && break
      sleep 1
    done
    [[ -S "$(host_socket)" ]] || { echo "meridian-host 没有创建控制套接字 $(host_socket)。" >&2; return 1; }
    "${SYSTEMCTL}" is-active --quiet meridian-host.service || return 1
  }
  return 0
}

# restore_host_bin SRC: atomically put SRC back as the host binary,
# root:root 0755 (backups keep it 0600), then restart meridian-host.
restore_host_bin() {
  local src="$1" dest tmp
  dest="$(host_bin)"
  tmp="${dest}.restore.$$"
  if [[ -n "${MERIDIAN_TEST_MODE:-}" ]]; then
    install -m 0755 "${src}" "${tmp}" || return 1
  else
    install -o root -g root -m 0755 "${src}" "${tmp}" || return 1
  fi
  mv -f "${tmp}" "${dest}" || { rm -f "${tmp}"; return 1; }
  restart_host_agent
}

# restore_backup DIR CID ENVFILE: put volumes, host binary, deploy/.env and
# the image of DIR back. The panel must be stopped.
restore_backup() {
  local dir="$1" cid="$2" envfile="$3" id vdata vsecrets
  id="$(basename "${dir}")"
  vdata="$(sed -n 's/^VOLUME_DATA=//p' "${dir}/meta.env")"
  vsecrets="$(sed -n 's/^VOLUME_SECRETS=//p' "${dir}/meta.env")"
  "${DOCKER}" image inspect "meridian-rollback:${id}" >/dev/null 2>&1 \
    || die "本机没有备份 ${id} 对应的镜像 meridian-rollback:${id}，不能回滚到它（数据与镜像必须成对恢复）。"
  # Two phases so a failing tar never leaves a volume half-restored: both
  # archives are first extracted into a staging directory inside their
  # volume (the current contents untouched); only when both succeeded are
  # the volumes swapped (renames on the same filesystem).
  local stage='set -e; rm -rf /v/.meridian-restore; mkdir /v/.meridian-restore; tar -xzf "/b/$1.tar.gz" -C /v/.meridian-restore'
  local unstage='rm -rf /v/.meridian-restore'
  local swap='set -e; rm -rf /v/.meridian-old; mkdir /v/.meridian-old
find /v -mindepth 1 -maxdepth 1 ! -name .meridian-restore ! -name .meridian-old -exec mv {} /v/.meridian-old/ \;
find /v/.meridian-restore -mindepth 1 -maxdepth 1 -exec mv {} /v/ \;
rmdir /v/.meridian-restore; rm -rf /v/.meridian-old'
  local pair staged=()
  for pair in "data:${vdata}" "secrets:${vsecrets}"; do
    if ! "${DOCKER}" run --rm --network none --entrypoint sh \
      -v "${pair#*:}:/v" -v "${dir}:/b:ro" "meridian-rollback:${id}" \
      -c "${stage}" sh "${pair%%:*}"; then
      for p in "${staged[@]+"${staged[@]}"}" "${pair}"; do
        "${DOCKER}" run --rm --network none --entrypoint sh -v "${p#*:}:/v" "meridian-rollback:${id}" \
          -c "${unstage}" sh "${p%%:*}" >/dev/null 2>&1 || true
      done
      die "解包备份到卷 ${pair#*:} 失败，两个卷都保持原样（备份仍在 ${dir}）。"
    fi
    staged+=("${pair}")
  done
  for pair in "${staged[@]}"; do
    "${DOCKER}" run --rm --network none --entrypoint sh \
      -v "${pair#*:}:/v" "meridian-rollback:${id}" \
      -c "${swap}" sh "${pair%%:*}" \
      || die "替换卷 ${pair#*:} 的内容失败（备份仍在 ${dir}）。"
  done
  if [[ -f "${dir}/deploy.env" ]]; then
    cp -p "${dir}/deploy.env" "${envfile}"
  fi
  env_set MERIDIAN_IMAGE "meridian-rollback:${id}" "${envfile}"
  if [[ -f "${dir}/meridian.host" ]]; then
    restore_host_bin "${dir}/meridian.host" \
      || die "恢复后 meridian-host 没有启动或不健康（journalctl -u meridian-host），宿主通道不可用。备份仍在 ${dir}。"
  fi
  : "${cid}"
}

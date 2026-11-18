#!/bin/bash
# Call the panel API from the gateway's shell, with the panel token read
# inside the container (it is never printed, put on any process command
# line - host or container - or copied to the host).
#
#   sudo bash deploy/debian/api.sh GET  /api/meta
#   sudo bash deploy/debian/api.sh POST /api/validate < body.json
#
# The body, if any, is read from stdin. Output is the response body; the
# exit status is non-zero on an HTTP error.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/debian/lib.sh
. "${here}/lib.sh"

[[ $# -eq 2 ]] || usage_die "用法：api.sh <GET|POST|PUT|DELETE> </api/路径>"
method="$1"
path="$2"
case "${method}" in GET|POST|PUT|DELETE) ;; *) usage_die "不支持的方法：${method}" ;; esac
[[ "${path}" =~ ^/api/[A-Za-z0-9/_.?=\&%-]*$ ]] || usage_die "路径必须以 /api/ 开头且不含空格或引号：${path}"
# No dot segments (curl would normalise "/api/../x" to "/x"), literal or
# percent-encoded (%2e / %2E), anywhere in the path or query.
api_path_has_dot_segment "${path}" && usage_die "路径不能含 . 或 .. 段：${path}"

require_root deploy/debian/api.sh

repo="$(cd "${here}/../.." && pwd)"
compose_init "${repo}/deploy/docker-compose.yml"
cid="$(panel_container)"
[[ -n "${cid}" ]] || die "没有找到面板容器。"
bind="$(panel_bind_of "${cid}")"
[[ -n "${bind}" ]] || die "读不到面板监听地址（meridian panel-bind）。"

data_flag=()
if [[ "${method}" != GET && ! -t 0 ]]; then
  data_flag=(--data-binary @- -H 'Content-Type: application/json')
fi
# Inside the container the shell reads the token file and writes the
# Authorization header into a fresh 0600 curl config file (mktemp, umask
# 077) with its printf builtin; curl reads the header from that file (-K),
# so the token is on no command line, and the file is removed when curl
# returns. The script passes only the method, URL and body (stdin).
# shellcheck disable=SC2016
exec "${DOCKER}" exec -i -e "M_METHOD=${method}" -e "M_URL=http://${bind}${path}" "${cid}" \
  sh -c 'umask 077
c="$(mktemp)" || exit 1
trap '"'"'rm -f "$c"'"'"' EXIT HUP INT TERM
t="$(cat "${MERIDIAN_DATA:-/var/lib/meridian}/panel.token")" || exit 1
printf '"'"'header = "Authorization: Bearer %s"\n'"'"' "$t" > "$c" || exit 1
unset t
curl -fsS -K "$c" -X "$M_METHOD" "$@" "$M_URL"' \
  sh "${data_flag[@]+"${data_flag[@]}"}"

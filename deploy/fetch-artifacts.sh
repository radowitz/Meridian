#!/bin/sh
# Meridian: fetch and verify the panel-delivered binaries at image build
# time (deploy/Dockerfile). The pins come from internal/artifacts/artifacts.lock,
# the same file the panel embeds.
#
#   fetch-artifacts.sh <lock> <local-dir> <out-dir>
#
# For every pinned binary: use <local-dir>/<basename of the URL> when the
# operator put the upstream download there (air-gapped builds), otherwise
# download it from the pinned GitHub release URL. The download must have the
# pinned source SHA-256, the extracted executable the pinned size and
# SHA-256; any mismatch fails the build. The executables are written to
# <out-dir>/<name>-<arch> with manifest.txt beside them.
set -eu

lock=$1
local_dir=$2
out=$3
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
manifest="$out/manifest.txt"
echo '# meridian-artifacts 1' > "$manifest.next"

sha() { sha256sum "$1" | cut -c1-64; }

grep -v '^[[:space:]]*#' "$lock" | grep -v '^[[:space:]]*$' | while read -r name version arch bin_sha size src_sha kind member url; do
  case "$name/$arch/$kind" in
    wstunnel/x86_64/tar.gz|wstunnel/aarch64/tar.gz|smartdns/x86_64/raw|smartdns/aarch64/raw|gost/x86_64/tar.gz|gost/aarch64/tar.gz) ;;
    *) echo "fetch-artifacts: unexpected lock entry $name $arch $kind" >&2; exit 1 ;;
  esac
  file=${url##*/}
  src="$work/$file"
  if [ -f "$local_dir/$file" ]; then
    echo "fetch-artifacts: $name $version $arch from the local copy $file"
    cp "$local_dir/$file" "$src"
  else
    echo "fetch-artifacts: $name $version $arch from $url"
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --max-time 300 -o "$src" "$url"
  fi
  got=$(sha "$src")
  if [ "$got" != "$src_sha" ]; then
    echo "fetch-artifacts: $file has SHA-256 $got, pinned $src_sha: refusing" >&2
    exit 1
  fi
  dest="$out/$name-$arch"
  case "$kind" in
    tar.gz)
      mkdir "$work/x-$name-$arch"
      tar -xzf "$src" -C "$work/x-$name-$arch" "$member"
      cp "$work/x-$name-$arch/$member" "$dest" ;;
    raw)
      cp "$src" "$dest" ;;
  esac
  chmod 0555 "$dest"
  got=$(sha "$dest")
  gotsize=$(wc -c < "$dest" | tr -d ' ')
  if [ "$got" != "$bin_sha" ] || [ "$gotsize" != "$size" ]; then
    echo "fetch-artifacts: $dest is $gotsize bytes with SHA-256 $got, pinned $size bytes $bin_sha: refusing" >&2
    exit 1
  fi
  echo "$name $version $arch $bin_sha $size $name-$arch" >> "$manifest.next"
done
mv "$manifest.next" "$manifest"
chmod 0444 "$manifest"
cat "$manifest"

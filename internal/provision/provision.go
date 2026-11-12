// Package provision builds the SSH bootstrap for a node the operator added.
// It never embeds real keys. Dry-run returns a script full of placeholders.
package provision

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	"golang.org/x/crypto/curve25519"

	"github.com/radowitz/meridian/internal/apply"
	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
)

const PrivatePlaceholder = compile.PrivateKeyPlaceholder

// Keypair is a WireGuard key generated in-process (not by shelling out).
type Keypair struct {
	Private string
	Public  string
}

func GenerateKeypair() (Keypair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return Keypair{}, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{
		Private: base64.StdEncoding.EncodeToString(priv[:]),
		Public:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// Script writes the node's rendered files and reloads WireGuard with
// syncconf when the interface already exists, so a NAT mapping is not torn down.
//
// WireGuard configs are written 0600 through a temp file. If a config still
// holds the private-key placeholder (a preview), the script refuses to run
// before it writes anything. When the node has a SmartDNS config, the
// resolver is installed before any file is written and must be active at the end.
func Script(nodeName string, files map[string]string) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Meridian provision\n")
	sb.WriteString("# node: " + oneLine(nodeName) + "\n")
	sb.WriteString("# Does not flush nftables, does not touch unrelated WireGuard interfaces,\n")
	sb.WriteString("# and does not install Cloudflare Mesh on the home gateway.\n")
	sb.WriteString("set -euo pipefail\n")
	sb.WriteString("umask 022\n")
	if apply.NeedsPrivateKey(files) {
		sb.WriteString("# PREVIEW ONLY: WireGuard configs still contain " + PrivatePlaceholder + ".\n")
		sb.WriteString("echo 'meridian: preview script still has the private-key placeholder; refusing to overwrite configs' >&2\n")
		sb.WriteString("exit 1\n")
	}
	sb.WriteString("export DEBIAN_FRONTEND=noninteractive\n")
	sb.WriteString("if ! command -v wg >/dev/null 2>&1; then\n")
	sb.WriteString("  apt-get update -y\n")
	sb.WriteString("  apt-get install -y wireguard-tools nftables iproute2\n")
	sb.WriteString("fi\n")
	sb.WriteString("if ! command -v wstunnel >/dev/null 2>&1; then\n")
	sb.WriteString("  echo 'wstunnel is missing. Install a pinned release from https://github.com/erebe/wstunnel/releases to /usr/local/bin/wstunnel' >&2\n")
	sb.WriteString("fi\n")
	_, hasDNS := files["/etc/smartdns/smartdns.conf"]
	if hasDNS {
		sb.WriteString(smartDNSInstall)
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sortStrings(paths)
	for _, p := range paths {
		clean, ok := safeHostPath(p)
		if !ok {
			fmt.Fprintf(&sb, "# rejected path %s\n", shellQuote(oneLine(p)))
			continue
		}
		body := files[p]
		delim := heredocDelim(body)
		mode, dirMode := "644", "755"
		switch {
		case strings.HasPrefix(clean, "/etc/wireguard/"):
			mode, dirMode = "600", "700"
		case strings.HasSuffix(clean, ".sh") || strings.Contains(clean, "/usr/local/sbin/"):
			mode = "755"
		}
		dir := dirOf(clean)
		fmt.Fprintf(&sb, "install -d -m %s %s\n", dirMode, shellQuote(dir))
		fmt.Fprintf(&sb, "tmp=$(mktemp %s)\n", shellQuote(dir+"/.meridian.XXXXXX"))
		fmt.Fprintf(&sb, "chmod %s \"$tmp\"\n", mode)
		fmt.Fprintf(&sb, "cat > \"$tmp\" <<'%s'\n%s%s\n", delim, ensureNL(body), delim)
		fmt.Fprintf(&sb, "mv -f \"$tmp\" %s\n", shellQuote(clean))
	}
	sb.WriteString("if [ -x /usr/local/sbin/meridian-up.sh ]; then\n")
	sb.WriteString("  /usr/local/sbin/meridian-up.sh\n")
	sb.WriteString("fi\n")
	if hasDNS {
		sb.WriteString(smartDNSStart)
	}
	sb.WriteString("echo MERIDIAN_PROVISION_OK\n")
	return sb.String()
}

// smartDNSInstall installs the resolver before any config is replaced. The
// distro package would otherwise start with its stock config (bind [::]:53 on
// a public host), so a temporary policy-rc.d holds the service until our
// config is in place, unless the host already has its own policy-rc.d.
const smartDNSInstall = `if ! command -v smartdns >/dev/null 2>&1; then
  hold_rc=0
  if [ ! -e /usr/sbin/policy-rc.d ]; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
    chmod 755 /usr/sbin/policy-rc.d
    hold_rc=1
  fi
  apt-get update -y || true
  if ! apt-get install -y -o Dpkg::Options::=--force-confold smartdns; then
    if [ "$hold_rc" = 1 ]; then rm -f /usr/sbin/policy-rc.d; fi
    echo 'smartdns is not installable from apt. Install a pinned release from https://github.com/pymumu/smartdns/releases, then rerun.' >&2
    exit 1
  fi
  if [ "$hold_rc" = 1 ]; then rm -f /usr/sbin/policy-rc.d; fi
fi
`

// smartDNSStart runs after meridian-up.sh, when the tunnel addresses the
// resolver binds to exist. meridian-up.sh on exits restarts it already; this
// covers other roles and proves the unit is active.
const smartDNSStart = `if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl enable smartdns.service >/dev/null 2>&1 || true
  if ! systemctl is-active --quiet smartdns.service; then
    systemctl restart smartdns.service
  fi
  if ! systemctl is-active --quiet smartdns.service; then
    echo 'smartdns.service is not active after provision' >&2
    systemctl status --no-pager smartdns.service >&2 || true
    exit 1
  fi
  echo MERIDIAN_SMARTDNS_ACTIVE
else
  echo 'no systemd: start smartdns -c /etc/smartdns/smartdns.conf yourself' >&2
fi
`

// FilesFor returns host paths (no nodes/<id> prefix) for one node.
func FilesFor(bundle map[string]string, nodeID string) map[string]string {
	prefix := "nodes/" + nodeID + "/"
	out := map[string]string{}
	for path, body := range bundle {
		if strings.HasPrefix(path, prefix) {
			out["/"+strings.TrimPrefix(path, prefix)] = body
		}
	}
	return out
}

// InjectPrivate replaces the placeholder in WireGuard configs. It fails when a
// config needs a key and private is empty or malformed, so a caller never
// ships a placeholder to a host.
//
// A remote-access secret placeholder (gateway only) is refused: SSH
// provisioning never carries credential-store secrets.
func InjectPrivate(files map[string]string, private string) (map[string]string, error) {
	out, err := apply.InjectPrivateKeys(files, private)
	if err != nil {
		return nil, err
	}
	for p, body := range out {
		if _, err := apply.InjectSecrets(strings.TrimPrefix(p, "/"), body, nil); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// KeyPolicy says how ResolveNodeKey may obtain a node's WireGuard key.
type KeyPolicy int

const (
	// KeyReuse uses the stored private key and fails when there is none
	// (remote provision with generate_keys=false, local rollback).
	KeyReuse KeyPolicy = iota
	// KeyGenerateIfMissing reuses a stored key, or generates one on the first
	// install when the node has neither a private nor a public key. A node
	// with only a public key fails: its private half lives elsewhere.
	KeyGenerateIfMissing
	// KeyRotate always generates a new pair (remote generate_keys=true).
	KeyRotate
)

// ResolveNodeKey returns the node's private key under policy. When it
// generates a key or fills in a missing public key, t is updated in place and
// changed is true; the caller must persist t. Errors never contain the key.
func ResolveNodeKey(t *model.Topology, nodeID string, policy KeyPolicy) (key string, changed bool, err error) {
	idx := -1
	for i := range t.Nodes {
		if t.Nodes[i].ID == nodeID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "", false, fmt.Errorf("节点 %s 不存在", nodeID)
	}
	n := &t.Nodes[idx]
	stored := strings.TrimSpace(n.PrivateKey)
	if stored == "***" {
		stored = ""
	}
	if policy != KeyRotate && stored != "" {
		pub, err := PublicFromPrivate(stored)
		if err != nil {
			return "", false, fmt.Errorf("节点 %s 已保存的私钥无效: %w", nodeID, err)
		}
		if strings.TrimSpace(n.PublicKey) == "" {
			n.PublicKey = pub
			return stored, true, nil
		}
		if strings.TrimSpace(n.PublicKey) != pub {
			return "", false, fmt.Errorf("节点 %s 已保存的私钥与公钥不匹配，拒绝安装", nodeID)
		}
		return stored, false, nil
	}
	switch policy {
	case KeyReuse:
		return "", false, fmt.Errorf("节点 %s 没有已保存的 WireGuard 私钥；首次装机请生成密钥", nodeID)
	case KeyGenerateIfMissing:
		if strings.TrimSpace(n.PublicKey) != "" {
			return "", false, fmt.Errorf("节点 %s 只有公钥没有私钥；请在拓扑中补私钥或清空公钥后重新生成", nodeID)
		}
	}
	kp, err := GenerateKeypair()
	if err != nil {
		return "", false, err
	}
	n.PrivateKey = kp.Private
	n.PublicKey = kp.Public
	return kp.Private, true, nil
}

// PublicFromPrivate derives the WireGuard public key.
func PublicFromPrivate(private string) (string, error) {
	if !apply.ValidPrivateKey(private) {
		return "", apply.ErrBadPrivateKey
	}
	raw, _ := base64.StdEncoding.DecodeString(private)
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", apply.ErrBadPrivateKey
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// Redact hides private keys in a script before it is shown in the panel.
func Redact(script, private string) string {
	return apply.RedactSecret(script, private)
}

// SSH execution lives in internal/sshexec: provisioning connects only
// through a managed server with a stored credential and a confirmed host
// key. This package builds the script and never dials.

func safeHostPath(p string) (string, bool) {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsAny(p, "\r\n\x00") {
		return "", false
	}
	clean := path.Clean(p)
	if clean != p || !apply.HostPathAllowed(clean) {
		return "", false
	}
	return clean, true
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func heredocDelim(body string) string {
	delim := "MERIDIAN_EOF"
	for strings.Contains(body, delim) {
		var buf [6]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return "MERIDIAN_EOF_FALLBACK"
		}
		delim = "MERIDIAN_EOF_" + hex.EncodeToString(buf[:])
	}
	return delim
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func dirOf(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func ensureNL(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j] < s[j-1] {
			s[j], s[j-1] = s[j-1], s[j]
			j--
		}
	}
}

// Package provision builds the SSH bootstrap for a node the operator added.
// It never embeds real keys. Dry-run returns a script full of placeholders.
package provision

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

const PrivatePlaceholder = "__MERIDIAN_PRIVATE_KEY__"

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
func Script(nodeName string, files map[string]string) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("# Meridian provision for " + nodeName + "\n")
	sb.WriteString("# Does not flush nftables, does not touch unrelated WireGuard interfaces,\n")
	sb.WriteString("# and does not install Cloudflare Mesh on the home gateway.\n")
	sb.WriteString("set -euo pipefail\n")
	sb.WriteString("export DEBIAN_FRONTEND=noninteractive\n")
	sb.WriteString("if ! command -v wg >/dev/null 2>&1; then\n")
	sb.WriteString("  apt-get update -y\n")
	sb.WriteString("  apt-get install -y wireguard-tools nftables iproute2\n")
	sb.WriteString("fi\n")
	sb.WriteString("if ! command -v wstunnel >/dev/null 2>&1; then\n")
	sb.WriteString("  echo 'wstunnel is missing. Install a pinned release from https://github.com/erebe/wstunnel/releases to /usr/local/bin/wstunnel' >&2\n")
	sb.WriteString("fi\n")
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sortStrings(paths)
	for _, p := range paths {
		if strings.Contains(p, "..") {
			continue
		}
		body := files[p]
		fmt.Fprintf(&sb, "install -d %s\n", shellQuote(dirOf(p)))
		fmt.Fprintf(&sb, "cat > %s <<'MERIDIAN_EOF'\n%sMERIDIAN_EOF\n", shellQuote(p), ensureNL(body))
		if strings.HasSuffix(p, ".sh") || strings.Contains(p, "/usr/local/sbin/") {
			fmt.Fprintf(&sb, "chmod 755 %s\n", shellQuote(p))
		} else {
			fmt.Fprintf(&sb, "chmod 644 %s\n", shellQuote(p))
		}
	}
	sb.WriteString("if [ -x /usr/local/sbin/meridian-up.sh ]; then\n")
	sb.WriteString("  /usr/local/sbin/meridian-up.sh\n")
	sb.WriteString("fi\n")
	sb.WriteString("echo MERIDIAN_PROVISION_OK\n")
	return sb.String()
}

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

// InjectPrivate replaces the placeholder in WireGuard configs.
func InjectPrivate(files map[string]string, private string) map[string]string {
	out := make(map[string]string, len(files))
	for k, v := range files {
		out[k] = strings.ReplaceAll(v, PrivatePlaceholder, private)
	}
	return out
}

// Redact hides private keys in a script before it is shown in the panel.
func Redact(script, private string) string {
	if private == "" {
		return script
	}
	return strings.ReplaceAll(script, private, PrivatePlaceholder)
}

type SSHRequest struct {
	Host          string
	Port          int
	User          string
	PrivateKeyPEM string
	TrustNewHost  bool
	KnownHosts    ssh.HostKeyCallback
}

// Run executes a script over SSH. The key PEM is not written to disk here.
func Run(req SSHRequest, script string) (string, error) {
	if req.Port == 0 {
		req.Port = 22
	}
	signer, err := ssh.ParsePrivateKey([]byte(req.PrivateKeyPEM))
	if err != nil {
		return "", fmt.Errorf("SSH 私钥无法解析")
	}
	callback := req.KnownHosts
	if callback == nil {
		if req.TrustNewHost {
			callback = ssh.InsecureIgnoreHostKey()
		} else {
			return "", fmt.Errorf("没有 known_hosts 记录。确认主机指纹后，用 trust_new_host 保存一次")
		}
	}
	cfg := &ssh.ClientConfig{
		User:            req.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: callback,
		Timeout:         20 * time.Second,
	}
	addr := net.JoinHostPort(req.Host, fmt.Sprintf("%d", req.Port))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if err := session.Run(script); err != nil {
		return stdout.String() + stderr.String(), fmt.Errorf("远程脚本失败: %w", err)
	}
	return stdout.String() + stderr.String(), nil
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

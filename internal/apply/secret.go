package apply

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/model"
)

// ErrMissingPrivateKey means a WireGuard config still carries the placeholder
// and no key was supplied. Installing it would break wg syncconf / wg-quick.
var ErrMissingPrivateKey = errors.New("缺少该节点的 WireGuard 私钥，已在写入任何主机配置前中止")

// ErrBadPrivateKey means the supplied key is not a 32-byte base64 value.
// The value itself is never echoed.
var ErrBadPrivateKey = errors.New("WireGuard 私钥格式不正确（应为 32 字节 base64）")

// ValidPrivateKey reports whether s is a WireGuard key: standard base64 of 32 bytes.
func ValidPrivateKey(s string) bool {
	if len(s) != 44 || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

func isWireGuardConf(rel string) bool {
	rel = strings.TrimPrefix(rel, "/")
	return strings.HasPrefix(rel, "etc/wireguard/") && strings.HasSuffix(rel, ".conf")
}

// InjectPrivateKey returns body with the placeholder replaced when rel is a
// WireGuard config. Other files are returned unchanged. It fails when the
// placeholder is present and key is empty or malformed.
func InjectPrivateKey(rel, body, key string) (string, error) {
	if !isWireGuardConf(rel) || !strings.Contains(body, compile.PrivateKeyPlaceholder) {
		return body, nil
	}
	if key == "" {
		return "", fmt.Errorf("%w（%s）", ErrMissingPrivateKey, strings.TrimPrefix(rel, "/"))
	}
	if !ValidPrivateKey(key) {
		return "", ErrBadPrivateKey
	}
	return strings.ReplaceAll(body, compile.PrivateKeyPlaceholder, key), nil
}

// InjectPrivateKeys applies InjectPrivateKey to a whole file map. Keys may be
// host paths with or without the leading slash.
func InjectPrivateKeys(files map[string]string, key string) (map[string]string, error) {
	out := make(map[string]string, len(files))
	for p, body := range files {
		v, err := InjectPrivateKey(p, body, key)
		if err != nil {
			return nil, err
		}
		out[p] = v
	}
	return out, nil
}

// NeedsPrivateKey reports whether any WireGuard config in files still holds the placeholder.
func NeedsPrivateKey(files map[string]string) bool {
	for p, body := range files {
		if isWireGuardConf(p) && strings.Contains(body, compile.PrivateKeyPlaceholder) {
			return true
		}
	}
	return false
}

// RedactSecret replaces every occurrence of key in s with the placeholder.
func RedactSecret(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, compile.PrivateKeyPlaceholder)
}

// ErrMissingSecret means a WireGuard config names a credential-store secret
// (remote-access key or pre-shared key) that was not supplied. Only the id
// is reported.
var ErrMissingSecret = errors.New("缺少 WireGuard 配置引用的密钥，已在写入任何主机配置前中止")

// InjectSecrets replaces every __MERIDIAN_SECRET_<id>__ placeholder of a
// WireGuard config with secrets[id]. Other files are returned unchanged;
// a placeholder outside etc/wireguard/ is refused (it must never reach a
// host file). A missing or malformed value fails; the value is never
// echoed.
func InjectSecrets(rel, body string, secrets map[string]string) (string, error) {
	ms := model.SecretPlaceholderRe.FindAllStringSubmatch(body, -1)
	if len(ms) == 0 {
		return body, nil
	}
	if !isWireGuardConf(rel) {
		return "", fmt.Errorf("拒绝安装：%s 含有密钥占位符", strings.TrimPrefix(rel, "/"))
	}
	for _, m := range ms {
		v, ok := secrets[m[1]]
		if !ok || v == "" {
			return "", fmt.Errorf("%w（%s 引用 %s）", ErrMissingSecret, strings.TrimPrefix(rel, "/"), m[1])
		}
		if !ValidPrivateKey(v) {
			return "", fmt.Errorf("WireGuard 密钥 %s 格式不正确（应为 32 字节 base64）", m[1])
		}
		body = strings.ReplaceAll(body, m[0], v)
	}
	return body, nil
}

// SecretRefs lists the credential-store ids the placeholders in text name.
func SecretRefs(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range model.SecretPlaceholderRe.FindAllStringSubmatch(text, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// RedactSecrets replaces the node key and every secret value in s with
// their placeholders.
func RedactSecrets(s, key string, secrets map[string]string) string {
	s = RedactSecret(s, key)
	for id, v := range secrets {
		if v != "" {
			s = strings.ReplaceAll(s, v, model.SecretPlaceholder(id))
		}
	}
	return s
}

func (a Applier) redactErr(err error) error {
	if err == nil {
		return nil
	}
	if msg := RedactSecrets(err.Error(), a.PrivateKey, a.Secrets); msg != err.Error() {
		return errors.New(msg)
	}
	return err
}

// ReferencedSecrets lists the credential-store ids that any stored copy of
// a configuration still names: the applied and previous snapshots, the
// installed copy (compensation and rollback rewrite it), a staged next copy
// and the transaction hold area. A secret in this set must not be deleted:
// a failed install or a rollback would need it to restore the old peers.
func (a Applier) ReferencedSecrets() (map[string]bool, error) {
	out := map[string]bool{}
	for _, dir := range []string{
		filepath.Join(a.data(), "applied"), filepath.Join(a.data(), "previous"),
		a.installedDir(), a.nextDir(), a.holdDir(),
	} {
		err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if info.IsDir() || !info.Mode().IsRegular() || info.Size() > 64<<20 {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, id := range SecretRefs(string(b)) {
				out[id] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

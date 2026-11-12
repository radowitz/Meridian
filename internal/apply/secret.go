package apply

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/compile"
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

func redactErr(err error, key string) error {
	if err == nil || key == "" || !strings.Contains(err.Error(), key) {
		return err
	}
	return errors.New(RedactSecret(err.Error(), key))
}

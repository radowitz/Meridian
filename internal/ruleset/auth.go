package ruleset

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Subscription authentication (docs/architecture.md「规则集合的订阅认证」).
//
// A private rule-set URL needs a credential: a bearer token, HTTP basic
// auth, or secret query parameters (the "?token=…" many subscription
// services use). The credential is not part of the URL the topology keeps:
//
//   - A stored URL may not carry user information ("https://user:pw@…"),
//     and may not carry a query parameter whose name looks like a secret
//     (SecretQueryKey: token, key, secret, password, auth, signature …).
//     CheckURL refuses both; the panel's API asks for the credential field
//     instead, the mihomo import and the stored-topology migration move such
//     parts into the credential store (SplitSecret).
//   - The credential lives only in the restricted credential store
//     (credentials.RuleSetAuth*), is write-only, and is handed to the
//     Fetcher at download time.
//   - The Fetcher sends it only over https and only to the exact origin
//     (scheme, host, port) of the configured URL: never to a mirror
//     candidate of the source policy, and a redirect to another origin
//     drops the Authorization header.
//   - Everything the panel shows about a download (errors, the URL a
//     version came from, the candidates) goes through Redact, which drops
//     user information and replaces any query string by "?…"; error text is
//     additionally scrubbed of every secret value.

// Auth kinds.
const (
	AuthBearer = "bearer"
	AuthBasic  = "basic"
	AuthQuery  = "query"
)

// Auth is a rule-set subscription credential (secret material).
type Auth struct {
	Kind     string `json:"kind"`
	Token    string `json:"token,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Query is appended to the URL ("k=v&k2=v2", already encoded).
	Query string `json:"query,omitempty"`
}

// Secrets lists the values to scrub from any text.
func (a *Auth) Secrets() []string {
	if a == nil {
		return nil
	}
	var out []string
	for _, v := range []string{a.Token, a.Password, a.Query} {
		if v != "" {
			out = append(out, v)
		}
	}
	if a.Query != "" {
		if q, err := url.ParseQuery(a.Query); err == nil {
			for _, vs := range q {
				for _, v := range vs {
					if len(v) >= 4 {
						out = append(out, v, url.QueryEscape(v))
					}
				}
			}
		}
	}
	return out
}

var authTokenRe = regexp.MustCompile(`^[\x21-\x7e]+$`)
var authUserRe = regexp.MustCompile(`^[\x21-\x39\x3b-\x7e]{1,255}$`) // printable, no ':'
var authPassRe = regexp.MustCompile(`^[\x20-\x7e]{1,1000}$`)

// Check validates a credential. Its message never contains the material.
func (a *Auth) Check() error {
	if a == nil {
		return errors.New("缺少认证信息")
	}
	switch a.Kind {
	case AuthBearer:
		if len(a.Token) > 4096 || !authTokenRe.MatchString(a.Token) {
			return errors.New("令牌必须是 1–4096 个可打印 ASCII 字符，不能有空白")
		}
	case AuthBasic:
		if !authUserRe.MatchString(a.Username) {
			return errors.New("用户名必须是 1–255 个可打印 ASCII 字符，不能有冒号")
		}
		if !authPassRe.MatchString(a.Password) {
			return errors.New("密码必须是 1–1000 个可打印 ASCII 字符")
		}
	case AuthQuery:
		if a.Query == "" || len(a.Query) > 2048 || strings.ContainsAny(a.Query, " \t\r\n#\"'`\\<>") {
			return errors.New("查询参数必须是 1–2048 个字符的 k=v&k2=v2，不能有空白、# 和引号")
		}
		q, err := url.ParseQuery(strings.TrimPrefix(a.Query, "?"))
		if err != nil || len(q) == 0 {
			return errors.New("查询参数不是 k=v&k2=v2 的形式")
		}
	default:
		return errors.New("认证方式只能是 bearer、basic 或 query")
	}
	return nil
}

// secretKeyRe: query parameter names that carry a secret.
var secretKeyRe = regexp.MustCompile(`(?i)(token|key|secret|pass|pwd|auth|sig|credential|session|ticket|otp|code)`)

// SecretQueryKey reports whether a query parameter name looks like a secret.
func SecretQueryKey(k string) bool { return secretKeyRe.MatchString(k) }

// ErrURLSecret is returned for a URL that carries a credential.
var ErrURLSecret = errors.New("URL 里带了用户名密码或令牌类参数：把它们放到「订阅认证」里（面板只在下载时附加，不显示、不导出），URL 只填公开部分")

// HasSecret reports whether a URL carries user information or a
// secret-looking query parameter.
func HasSecret(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return strings.Contains(raw, "@")
	}
	if u.User != nil {
		return true
	}
	for k := range u.Query() {
		if SecretQueryKey(k) {
			return true
		}
	}
	return false
}

// SplitSecret moves the credential parts out of a URL: user information
// becomes basic auth, secret-looking query parameters a query credential
// (their order kept). auth is nil when the URL has none. A URL with both
// user information and secret parameters is refused (set it up by hand).
func SplitSecret(raw string) (clean string, auth *Auth, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", nil, errors.New("URL 必须是带主机名的 http:// 或 https://")
	}
	var keep, secret []string
	if u.RawQuery != "" {
		for _, part := range strings.Split(u.RawQuery, "&") {
			if part == "" {
				continue
			}
			k := part
			if i := strings.IndexByte(part, '='); i >= 0 {
				k = part[:i]
			}
			if dk, err := url.QueryUnescape(k); err == nil {
				k = dk
			}
			if SecretQueryKey(k) {
				secret = append(secret, part)
			} else {
				keep = append(keep, part)
			}
		}
	}
	if u.User != nil {
		pw, _ := u.User.Password()
		auth = &Auth{Kind: AuthBasic, Username: u.User.Username(), Password: pw}
		u.User = nil
	}
	if len(secret) > 0 {
		if auth != nil {
			return "", nil, errors.New("URL 同时带了用户名密码和令牌参数：请手工添加规则集并设置认证")
		}
		auth = &Auth{Kind: AuthQuery, Query: strings.Join(secret, "&")}
	}
	u.RawQuery = strings.Join(keep, "&")
	u.Fragment = ""
	if auth != nil {
		if err := auth.Check(); err != nil {
			return "", nil, errors.New("URL 里的认证部分不能使用：" + err.Error())
		}
	}
	return u.String(), auth, nil
}

// Redact is a URL for display: no user information, no fragment, any query
// string replaced by "?…".
func Redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexAny(raw, "?#@"); i >= 0 {
			return raw[:i] + "…"
		}
		return raw
	}
	u.User = nil
	u.Fragment = ""
	q := u.RawQuery != ""
	u.RawQuery = ""
	s := u.String()
	if q {
		s += "?…"
	}
	return s
}

// Scrub replaces every secret value in s.
func Scrub(s string, secrets ...string) string {
	for _, v := range secrets {
		if len(v) >= 3 {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	return s
}

// Origin is scheme://host[:port] of a URL ("" when it does not parse): the
// only place a subscription credential is sent.
func Origin(raw string) string { return origin(raw) }

// origin is scheme://host[:port] of a URL ("" when it does not parse).
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

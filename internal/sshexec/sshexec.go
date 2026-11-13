// Package sshexec is the only way the panel opens an SSH connection to a
// managed server (provisioning, Mesh deployment and withdrawal, discovery
// and the connection test). A caller names a server by ID; the address,
// port, user and credential come from the credential store, and the secret
// is read only after the host has presented its pinned key, inside the
// authentication callback. Nothing in a request can supply key material, a
// target or a command: scripts are built by the panel, the connection
// test runs one fixed command, and the install preflight runs one fixed,
// read-only script (internal/preflight) whose only arguments are validated
// host paths (RunPreflight).
//
// Host keys. Discover connects only far enough to read the host key (no
// authentication is attempted, nothing is executed) and records it with
// credentials.Store.ObserveHostKey. Every other operation requires the
// server's key to be "trusted" (confirmed by the operator) before it
// connects, and the key presented during the handshake must be that one;
// otherwise the connection is closed before authentication and the store
// marks the server "mismatch" (the pin is kept). Re-trusting is an explicit
// operator action (POST /api/servers/{id}/host-key/trust).
package sshexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/preflight"
)

// Error codes (stable, for the panel).
const (
	CodeNotFound      = credentials.CodeNotFound
	CodeNoCredential  = credentials.CodeNoCredential
	CodeUntrusted     = "host_key_untrusted"
	CodeMismatch      = credentials.CodeHostKeyMismatch
	CodePinMismatch   = "host_key_not_pinned_by_deployment"
	CodeTargetChanged = "target_changed"
	CodeUnreachable   = "unreachable"
	CodeTimeout       = "timeout"
	CodeAuthFailed    = "auth_failed"
	// CodeAuthMethodUnavailable: the server never offered the credential's
	// login method (for example password login with PasswordAuthentication
	// no), so the credential itself was not tried. Distinct from
	// CodeAuthFailed, where the server tried and rejected it.
	CodeAuthMethodUnavailable = "auth_method_unavailable"
	CodeCommandFailed         = "command_failed"
	CodeNotSSH                = "not_ssh"
	// CodeRateLimited: the server answered "Not allowed at this time"
	// before its SSH version line and closed the connection (OpenSSH
	// PerSourcePenalties). Nothing was authenticated or run; the panel does
	// not connect to that endpoint again for Error.RetryAfter seconds.
	CodeRateLimited = "ssh_rate_limited"
)

// Error is every error this package returns. Msg is scrubbed of the
// credential's secrets.
type Error struct {
	Code string
	Msg  string
	// RetryAfter (seconds) is set with CodeRateLimited: how long the panel
	// will not connect to the endpoint again.
	RetryAfter int
}

func (e *Error) Error() string { return e.Msg }

func errf(code, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// RetryAfterOf returns the RetryAfter of an *Error (or 0).
func RetryAfterOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.RetryAfter
	}
	return 0
}

// CodeOf returns the code of an *Error (or "").
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Auth methods reported in results.
const (
	AuthPassword = model.AuthPassword
	AuthKey      = model.AuthKey
)

// Connector opens SSH connections to managed servers.
type Connector struct {
	Store *credentials.Store
	// DialTimeout bounds the TCP connect (default 10s); HandshakeTimeout
	// bounds key exchange and authentication (default 20s).
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	// Dial replaces the TCP dialer (tests only).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// MaxOutput caps the captured output (default 1 MiB).
	MaxOutput int
	// Pool, when set, lends authenticated connections across the steps of
	// one operation flow and remembers rate-limited endpoints (see Pool).
	// Nil: every operation opens and closes its own connection.
	Pool *Pool
}

// Target is what an operation connects to: a server, optionally with the
// credential and the identity a deployment pinned. When Address is set the
// server's current address, port and user must equal Address, Port and
// User, and when Fingerprint is set the host must present exactly it (in
// addition to being trusted).
type Target struct {
	ServerID     string
	CredentialID string // "" = the server's current credential
	Address      string
	Port         int
	User         string
	Fingerprint  string
}

// Result is a finished remote run. Output is scrubbed.
type Result struct {
	Output       string
	AuthMethod   string
	Fingerprint  string
	ServerID     string
	CredentialID string
	// Reused: the operation ran on a pooled connection opened earlier in
	// the same flow (no new login).
	Reused bool
}

// Discovery is what Discover saw.
type Discovery struct {
	KeyType     string       `json:"key_type"`
	Fingerprint string       `json:"fingerprint"`
	Server      model.Server `json:"-"`
	// MatchesPinned is true when the server is trusted and presented the
	// pinned key.
	MatchesPinned bool `json:"matches_pinned"`
}

func (c *Connector) dialTimeout() time.Duration {
	if c.DialTimeout > 0 {
		return c.DialTimeout
	}
	return 10 * time.Second
}

func (c *Connector) handshakeTimeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return 20 * time.Second
}

func (c *Connector) dial(ctx context.Context, sv model.Server) (net.Conn, error) {
	addr := net.JoinHostPort(sv.Address, strconv.Itoa(sv.Port))
	dctx, cancel := context.WithTimeout(ctx, c.dialTimeout())
	defer cancel()
	var conn net.Conn
	var err error
	if c.Dial != nil {
		conn, err = c.Dial(dctx, "tcp", addr)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(dctx, "tcp", addr)
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return nil, errf(CodeTimeout, "连接 %s 超时", addr)
		}
		return nil, errf(CodeUnreachable, "无法连接 %s：%s", addr, plainNetErr(err))
	}
	return conn, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// plainNetErr drops the address prefix of a *net.OpError (the address is
// already in the message) and keeps the cause.
func plainNetErr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

var errDiscovered = errors.New("meridian: host key read, discovery stops before authentication")

// Discover reads the server's host key without authenticating and records
// it (unknown/discovered → discovered with this key; trusted with the same
// key → stays trusted; trusted with another key → mismatch, pin kept).
// Nothing is executed. A mismatch is reported in the result, not as an
// error: discovery's job is to show what the host presents.
func (c *Connector) Discover(ctx context.Context, serverID string) (Discovery, error) {
	sv, err := c.Store.Server(serverID)
	if err != nil {
		return Discovery{}, errf(CodeNotFound, "%s", err.Error())
	}
	ep := endpoint(sv.Address, sv.Port)
	if left := c.Pool.cooling(ep); left > 0 {
		return Discovery{}, rateLimitedErr(sv.Name, ep, left)
	}
	raw, err := c.dial(ctx, sv)
	if err != nil {
		return Discovery{}, err
	}
	conn := newBannerConn(raw)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.handshakeTimeout()))
	var seen ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: sv.User,
		// No Auth: the handshake is aborted in the host key callback,
		// before the client would offer any method.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key
			return errDiscovered
		},
		Timeout: c.handshakeTimeout(),
	}
	sc, chans, reqs, herr := ssh.NewClientConn(conn, net.JoinHostPort(sv.Address, strconv.Itoa(sv.Port)), cfg)
	if herr == nil {
		// Cannot happen without auth methods; close defensively.
		ssh.NewClient(sc, chans, reqs).Close()
	}
	if seen == nil {
		pre, sawSSH := conn.preBanner()
		if !sawSSH && rateLimitLine(pre) {
			c.Pool.rateLimited(ep)
			return Discovery{}, rateLimitedErr(sv.Name, ep, c.Pool.cooldown())
		}
		if herr != nil && isTimeout(herr) {
			return Discovery{}, errf(CodeTimeout, "%s 的 SSH 握手超时", sv.Name)
		}
		return Discovery{}, errf(CodeNotSSH, "%s:%d 没有完成 SSH 密钥交换，读不到主机公钥%s", sv.Address, sv.Port, preBannerNote(pre, sawSSH))
	}
	fp := ssh.FingerprintSHA256(seen)
	got, oerr := c.Store.ObserveHostKey(sv.ID, seen.Type(), fp)
	if oerr != nil && credentials.CodeHostKeyMismatch != codeOfCred(oerr) {
		return Discovery{}, oerr
	}
	if oerr != nil {
		got, _ = c.Store.Server(sv.ID)
	}
	return Discovery{KeyType: seen.Type(), Fingerprint: fp, Server: got,
		MatchesPinned: got.HostKey.State == model.HostKeyTrusted && got.HostKey.Fingerprint == fp}, nil
}

func codeOfCred(err error) string {
	var ce *credentials.Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

// session is one authenticated connection.
type session struct {
	client  *ssh.Client
	method  string
	fp      string
	secrets []string
	credID  string
	created time.Time
}

// endpoint is the dial address of a server.
func endpoint(address string, port int) string {
	return net.JoinHostPort(address, strconv.Itoa(port))
}

// preBannerNote describes text a server sent instead of (or before) its
// SSH version line, for an error message.
func preBannerNote(pre string, sawSSH bool) string {
	if sawSSH || pre == "" {
		return ""
	}
	return "（服务器没有发 SSH 版本行，只回复了：«" + pre + "»）"
}

// resolved is a target checked against the store, ready to dial.
type resolved struct {
	t      Target
	sv     model.Server
	credID string
	meta   credentials.SSHCredential
	key    poolKey
}

// connect checks the target, dials, verifies the host key against the
// trusted pin (recording what was seen) and authenticates with the stored
// credential, whose secret is read only after the host key was accepted.
func (c *Connector) connect(ctx context.Context, t Target) (*session, error) {
	r, err := c.resolve(t)
	if err != nil {
		return nil, err
	}
	return c.handshake(ctx, r)
}

// resolve performs every check that needs no network: the server exists,
// matches the pinned endpoint, its host key is trusted (and the deployment
// pin, when given), and the credential exists. The result names the exact
// identity a connection authenticated with it is bound to.
func (c *Connector) resolve(t Target) (resolved, error) {
	sv, err := c.Store.Server(t.ServerID)
	if err != nil {
		return resolved{}, errf(CodeNotFound, "%s", err.Error())
	}
	if t.Address != "" {
		port := t.Port
		if port == 0 {
			port = 22
		}
		user := t.User
		if user == "" {
			user = "root"
		}
		if sv.Address != t.Address || sv.Port != port || sv.User != user {
			return resolved{}, errf(CodeTargetChanged, "服务器 %s 现在是 %s@%s:%d，不是部署时固定的 %s@%s:%d；拒绝连接", sv.Name, sv.User, sv.Address, sv.Port, user, t.Address, port)
		}
	}
	switch sv.HostKey.State {
	case model.HostKeyTrusted:
	case model.HostKeyMismatch:
		return resolved{}, errf(CodeMismatch, "服务器 %s 上次出示的主机指纹 %s 与固定的 %s 不一致；核实后重新确认指纹，或清除记录重新发现", sv.Name, sv.HostKey.Seen, sv.HostKey.Fingerprint)
	default:
		return resolved{}, errf(CodeUntrusted, "服务器 %s 的主机指纹还没有确认（状态 %s）；先「发现指纹」并核对确认", sv.Name, sv.HostKey.State)
	}
	if t.Fingerprint != "" && sv.HostKey.Fingerprint != t.Fingerprint {
		return resolved{}, errf(CodePinMismatch, "服务器 %s 现在信任的主机指纹 %s 不是部署时固定的 %s；拒绝连接", sv.Name, sv.HostKey.Fingerprint, t.Fingerprint)
	}
	credID := t.CredentialID
	if credID == "" {
		credID = sv.CredentialID
	}
	if credID == "" {
		return resolved{}, errf(CodeNoCredential, "服务器 %s 还没有选择 SSH 凭据", sv.Name)
	}
	meta, err := c.Store.SSHCredential(credID)
	if err != nil {
		return resolved{}, errf(CodeNotFound, "服务器 %s 使用的 SSH 凭据 %s 不存在", sv.Name, credID)
	}
	gen, err := c.Store.SSHCredentialGen(credID)
	if err != nil {
		return resolved{}, errf(CodeNotFound, "服务器 %s 使用的 SSH 凭据 %s 不存在", sv.Name, credID)
	}
	return resolved{t: t, sv: sv, credID: credID, meta: meta, key: poolKey{ServerID: sv.ID, Address: sv.Address, Port: sv.Port, User: sv.User,
		Fingerprint: sv.HostKey.Fingerprint, KeyType: sv.HostKey.KeyType, PinnedAt: sv.HostKey.PinnedAt, CredentialID: credID, CredentialGn: gen}}, nil
}

// handshake dials the resolved target and authenticates.
func (c *Connector) handshake(ctx context.Context, r resolved) (*session, error) {
	t, sv, credID, meta := r.t, r.sv, r.credID, r.meta
	ep := endpoint(sv.Address, sv.Port)
	if left := c.Pool.cooling(ep); left > 0 {
		return nil, rateLimitedErr(sv.Name, ep, left)
	}
	s := &session{credID: credID, created: time.Now()}
	var hostErr error
	var authMu sync.Mutex
	var auth *credentials.SSHAuth
	var authErr error
	resolve := func() (*credentials.SSHAuth, error) {
		authMu.Lock()
		defer authMu.Unlock()
		if auth == nil && authErr == nil {
			a, err := c.Store.ResolveSSHWith(sv.ID, credID)
			if err != nil {
				authErr = err
			} else {
				auth = &a
				s.secrets = a.Secrets()
			}
		}
		return auth, authErr
	}
	// tried records whether the credential's own method was used at all
	// (the client only calls a method's callback when the server offers it);
	// offered collects the other methods the server offered, learned from
	// probe-only methods that never send anything and only record that the
	// server listed them.
	var tried bool
	var offered []string
	markTried := func() { authMu.Lock(); tried = true; authMu.Unlock() }
	probe := func(m string) {
		authMu.Lock()
		defer authMu.Unlock()
		for _, o := range offered {
			if o == m {
				return
			}
		}
		offered = append(offered, m)
	}
	var methods []ssh.AuthMethod
	switch meta.Kind {
	case credentials.KindPassword:
		s.method = AuthPassword
		pw := func() (string, error) {
			markTried()
			a, err := resolve()
			if err != nil {
				return "", err
			}
			return a.Password, nil
		}
		methods = append(methods, ssh.PasswordCallback(pw),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					if echos[i] {
						// Only hidden prompts get the password.
						return nil, errors.New("unexpected visible prompt")
					}
					p, err := pw()
					if err != nil {
						return nil, err
					}
					answers[i] = p
				}
				return answers, nil
			}))
	case credentials.KindPrivateKey:
		s.method = AuthKey
		methods = append(methods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			markTried()
			a, err := resolve()
			if err != nil {
				return nil, err
			}
			var signer ssh.Signer
			if a.Passphrase != "" {
				signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(a.PrivateKey), []byte(a.Passphrase))
			} else {
				signer, err = ssh.ParsePrivateKey([]byte(a.PrivateKey))
			}
			if err != nil {
				return nil, errors.New("保存的私钥无法解析（口令错误或格式不支持）")
			}
			return []ssh.Signer{signer}, nil
		}))
	default:
		return nil, errf(CodeNoCredential, "SSH 凭据 %s 的种类 %q 不支持", credID, meta.Kind)
	}
	// Probe-only methods come after the real ones, so they run only when the
	// server offers them and the credential's method is not offered or has
	// been rejected. Their callbacks fail before anything is sent (password,
	// publickey); keyboard-interactive sends only the method request, never
	// an answer.
	if meta.Kind == credentials.KindPassword {
		methods = append(methods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			probe("publickey")
			return nil, errProbeOnly
		}))
	} else {
		methods = append(methods,
			ssh.PasswordCallback(func() (string, error) {
				probe("password")
				return "", errProbeOnly
			}),
			ssh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
				probe("keyboard-interactive")
				return nil, errProbeOnly
			}))
	}
	pinned, pinnedType := sv.HostKey.Fingerprint, sv.HostKey.KeyType
	cfg := &ssh.ClientConfig{
		User: sv.User,
		Auth: methods,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			now, oerr := c.Store.ObserveHostKey(sv.ID, key.Type(), fp)
			switch {
			case oerr != nil && codeOfCred(oerr) == credentials.CodeHostKeyMismatch:
				hostErr = errf(CodeMismatch, "%s", oerr.Error())
			case oerr != nil:
				hostErr = errf(CodeMismatch, "记录主机指纹失败，拒绝连接：%s", oerr.Error())
			case now.HostKey.State != model.HostKeyTrusted || now.HostKey.Fingerprint != pinned || fp != pinned:
				hostErr = errf(CodeUntrusted, "%s 出示的主机指纹 %s 不是已确认的 %s；拒绝连接", sv.Name, fp, pinned)
			case t.Fingerprint != "" && fp != t.Fingerprint:
				hostErr = errf(CodePinMismatch, "%s 出示的主机指纹 %s 不是部署时固定的 %s；拒绝连接", sv.Name, fp, t.Fingerprint)
			}
			if hostErr != nil {
				return hostErr
			}
			s.fp = fp
			return nil
		},
		HostKeyAlgorithms: hostKeyAlgos(pinnedType),
		Timeout:           c.handshakeTimeout(),
	}
	raw, err := c.dial(ctx, sv)
	if err != nil {
		return nil, err
	}
	conn := newBannerConn(raw)
	_ = conn.SetDeadline(time.Now().Add(c.handshakeTimeout()))
	sc, chans, reqs, err := ssh.NewClientConn(conn, ep, cfg)
	if err != nil {
		conn.Close()
		pre, sawSSH := conn.preBanner()
		switch {
		case hostErr != nil:
			return nil, hostErr
		case !sawSSH && rateLimitLine(pre):
			// Refused before the version exchange: no key was seen, no
			// credential was read or sent.
			c.Pool.rateLimited(ep)
			return nil, rateLimitedErr(sv.Name, ep, c.Pool.cooldown())
		case authErr != nil:
			return nil, errf(CodeAuthFailed, "%s", credentials.Scrub(authErr.Error(), s.secrets...))
		case errors.Is(err, errProbeOnly) || strings.Contains(err.Error(), "unable to authenticate"):
			authMu.Lock()
			used, others := tried, append([]string(nil), offered...)
			authMu.Unlock()
			if !used {
				return nil, errf(CodeAuthMethodUnavailable, "%s", methodUnavailableMsg(sv.Name, s.method, others))
			}
			return nil, errf(CodeAuthFailed, "%s 拒绝了 %s 的%s登录（服务器接受%s登录，但这份凭据没有通过）", sv.Name, sv.User, methodName(s.method), methodName(s.method))
		case isTimeout(err):
			return nil, errf(CodeTimeout, "%s 的 SSH 握手超时", sv.Name)
		default:
			return nil, errf(CodeUnreachable, "%s 的 SSH 握手失败：%s%s", sv.Name, credentials.Scrub(err.Error(), s.secrets...), preBannerNote(credentials.Scrub(pre, s.secrets...), sawSSH))
		}
	}
	conn.stop()
	_ = conn.SetDeadline(time.Time{})
	s.client = ssh.NewClient(sc, chans, reqs)
	return s, nil
}

// hostKeyAlgos asks the server for the pinned key's algorithm first so a
// host with several keys presents the one that was confirmed. For RSA the
// SHA-2 signature variants are offered.
func hostKeyAlgos(keyType string) []string {
	switch keyType {
	case "":
		return nil
	case ssh.KeyAlgoRSA:
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	default:
		return []string{keyType}
	}
}

// errProbeOnly is returned by the probe-only auth methods.
var errProbeOnly = errors.New("probe only: method offered by the server, not used")

// methodUnavailableMsg says that the server does not accept the
// credential's login method, which methods it does offer (when known) and
// what to do.
func methodUnavailableMsg(server, method string, offered []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s 不接受%s登录，这份凭据没有被尝试", server, methodName(method))
	if len(offered) > 0 {
		fmt.Fprintf(&b, "（服务器提供的登录方式：%s）", strings.Join(offered, "、"))
	}
	if method == AuthPassword {
		b.WriteString("。改用 SSH 密钥凭据，或在服务器上开启密码登录（sshd_config 里 PasswordAuthentication yes，然后重载 sshd）")
	} else {
		b.WriteString("。改用密码凭据，或在服务器上开启公钥登录（sshd_config 里 PubkeyAuthentication yes，然后重载 sshd）")
	}
	return b.String()
}

func methodName(m string) string {
	if m == AuthPassword {
		return "密码"
	}
	return "密钥"
}

type capWriter struct {
	buf bytes.Buffer
	n   int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.n - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

// run executes command (with stdin) on an authenticated session: a pooled
// connection of exactly this identity when the Connector has a Pool and one
// is idle (and fresh is false), else a new one. On success the connection
// goes back to the pool; after any error it is closed.
func (c *Connector) run(ctx context.Context, t Target, command string, stdin io.Reader) (res Result, err error) {
	return c.runOn(ctx, t, command, stdin, false)
}

func (c *Connector) runOn(ctx context.Context, t Target, command string, stdin io.Reader, fresh bool) (res Result, err error) {
	r, err := c.resolve(t)
	if err != nil {
		// The server is not operable under any identity now (deleted,
		// pin cleared or in mismatch, credential gone): nothing of it is
		// kept for later.
		c.Pool.InvalidateServer(t.ServerID)
		return Result{ServerID: t.ServerID}, err
	}
	var s *session
	reused := false
	if c.Pool != nil {
		if fresh {
			// A fresh login was asked for: the idle one of this identity
			// would only be a second connection to the same host.
			c.Pool.drop(func(k poolKey) bool { return k == r.key })
		} else if s = c.Pool.take(r.key); s != nil {
			reused = true
		}
	}
	if s == nil {
		if s, err = c.handshake(ctx, r); err != nil {
			return Result{ServerID: t.ServerID}, err
		}
	}
	defer func() {
		if err == nil && c.Pool != nil && ctx.Err() == nil {
			c.Pool.put(r.key, s)
			return
		}
		s.client.Close()
	}()
	res = Result{AuthMethod: s.method, Fingerprint: s.fp, ServerID: t.ServerID, CredentialID: s.credID, Reused: reused}
	sess, err := s.client.NewSession()
	if err != nil {
		return res, errf(CodeCommandFailed, "打开 SSH 会话失败：%s", credentials.Scrub(err.Error(), s.secrets...))
	}
	defer sess.Close()
	max := c.MaxOutput
	if max <= 0 {
		max = 1 << 20
	}
	out := &capWriter{n: max}
	sess.Stdout, sess.Stderr = out, out
	if stdin != nil {
		sess.Stdin = stdin
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		s.client.Close()
		res.Output = credentials.Scrub(out.buf.String(), s.secrets...)
		return res, errf(CodeTimeout, "远程执行超时：%v", ctx.Err())
	}
	res.Output = credentials.Scrub(out.buf.String(), s.secrets...)
	if err != nil {
		return res, errf(CodeCommandFailed, "远程执行失败：%s", credentials.Scrub(err.Error(), s.secrets...))
	}
	return res, nil
}

// RunScript sends a panel-built script to "bash -s" on stdin, so nothing
// in it (a WireGuard private key, a Mesh node token) appears in the remote
// process list.
func (c *Connector) RunScript(ctx context.Context, t Target, script string) (Result, error) {
	return c.run(ctx, t, "bash -s", strings.NewReader(script))
}

// TestCommand is the fixed command of the connection test: it reads the
// machine architecture, the kernel release and the OS name, and changes
// nothing.
const TestCommand = `printf 'MERIDIAN_ARCH=%s\nMERIDIAN_KERNEL=%s\n' "$(uname -m)" "$(uname -r)"; grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null || true`

// TestTimeout bounds the whole connection test.
const TestTimeout = 30 * time.Second

// Test authenticates with the stored credential and runs TestCommand. The
// result is returned whatever happened (the caller records it); err is
// non-nil only when the test could not be attempted (server unknown, key
// not trusted, no credential): those are not connection results.
func (c *Connector) Test(ctx context.Context, serverID string) (model.ConnectionTest, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, TestTimeout)
	defer cancel()
	// Always a fresh login (the test is about whether logging in works);
	// the connection then stays in the pool for the next step.
	res, err := c.runOn(ctx, Target{ServerID: serverID}, TestCommand, nil, true)
	ct := model.ConnectionTest{AuthMethod: res.AuthMethod, DurationMS: time.Since(start).Milliseconds()}
	if err != nil {
		switch CodeOf(err) {
		case CodeNotFound, CodeUntrusted, CodeNoCredential:
			return ct, err
		}
		ct.Code, ct.Error, ct.RetryAfter = CodeOf(err), err.Error(), RetryAfterOf(err)
		if ct.Code == "" {
			ct.Code = CodeCommandFailed
		}
		return ct, nil
	}
	for _, line := range strings.Split(res.Output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "MERIDIAN_ARCH="):
			ct.Arch = clean(strings.TrimPrefix(line, "MERIDIAN_ARCH="))
		case strings.HasPrefix(line, "MERIDIAN_KERNEL="):
			ct.Kernel = clean(strings.TrimPrefix(line, "MERIDIAN_KERNEL="))
		case strings.HasPrefix(line, "PRETTY_NAME="):
			ct.OS = clean(strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"'`))
		}
	}
	if ct.Arch == "" {
		ct.Code, ct.Error = CodeCommandFailed, "登录成功，但测试命令没有返回预期输出"
		return ct, nil
	}
	ct.OK = true
	return ct, nil
}

// clean keeps a short printable value.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if r := []rune(out); len(r) > 128 {
		out = string(r[:128])
	}
	return out
}

// GroupStateCommand is the fixed, read-only command that reads the hub's
// region-group state (written by the hub's failover script, see
// internal/compile hub_state.go): the hub's clock, the deployed group plan
// identifier and every group report, framed by a header and an end line.
// It takes no input. Output is cut at GroupStateMax+1 bytes on the hub, so
// a longer answer is recognisable as oversized (internal/hubstate parses
// it).
const GroupStateCommand = `{ printf 'meridian-group-state 1\nnow %s\n' "$(date +%s)"; cat /run/meridian/group-plan; for f in /run/meridian/group/*/report; do if [ -f "$f" ]; then cat "$f"; fi; done; echo meridian-group-state-end; } 2>/dev/null | head -c 65537`

// GroupStateMax is the largest accepted answer of GroupStateCommand.
const GroupStateMax = 64 << 10

// GroupStateTimeout bounds the whole read.
const GroupStateTimeout = 30 * time.Second

// ReadGroupState logs in to the server with its stored credential (trusted,
// pinned host key required) and runs GroupStateCommand. The output is
// returned scrubbed and capped at GroupStateMax+1 bytes; the caller parses
// it. t.ServerID is required; the caller pins t.Address/Port/User and
// t.Fingerprint to the hub identity it captured, so a server edited or
// re-pinned in the meantime is refused (target_changed /
// host_key_not_pinned_by_deployment) instead of being read under the old
// identity. No command or credential comes from t.
func (c *Connector) ReadGroupState(ctx context.Context, t Target) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, GroupStateTimeout)
	defer cancel()
	cc := *c
	cc.MaxOutput = GroupStateMax + 1
	res, err := cc.run(ctx, Target{ServerID: t.ServerID, Address: t.Address, Port: t.Port, User: t.User, Fingerprint: t.Fingerprint}, GroupStateCommand, nil)
	if err != nil {
		return "", err
	}
	return res.Output, nil
}

// PreflightTimeout bounds one remote preflight (connect, login, run).
const PreflightTimeout = 90 * time.Second

// preflightArg is the only argument shape the preflight command accepts:
// a single-quoted absolute path of letters, digits and ._/@+-
// (preflight.Args). Anything else is refused before connecting.
var preflightArg = regexp.MustCompile(`^'/[A-Za-z0-9._/@+-]{1,200}'$`)

// CodeBadArgs: the preflight arguments were refused before connecting.
const CodeBadArgs = "preflight_bad_args"

// RunPreflight sends the fixed read-only preflight script to "bash -s --
// <paths>" on the target (trusted, pinned host key; t pins the identity
// the caller captured) and returns its report, capped at
// preflight.MaxReport+1 bytes so an oversized answer is recognisable. The
// script text is preflight.Script(); args come from preflight.Args and are
// checked again here.
func (c *Connector) RunPreflight(ctx context.Context, t Target, args []string) (Result, error) {
	if len(args) > preflight.MaxPaths {
		return Result{ServerID: t.ServerID}, errf(CodeBadArgs, "预检参数过多")
	}
	for _, a := range args {
		if !preflightArg.MatchString(a) || strings.Contains(a, "..") {
			return Result{ServerID: t.ServerID}, errf(CodeBadArgs, "预检参数不合法：%q", a)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, PreflightTimeout)
	defer cancel()
	cc := *c
	cc.MaxOutput = preflight.MaxReport + 1
	command := "bash -s"
	if len(args) > 0 {
		command += " -- " + strings.Join(args, " ")
	}
	return cc.run(ctx, t, command, strings.NewReader(preflight.Script()))
}

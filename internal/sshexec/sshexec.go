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

	"github.com/radowitz/meridian/internal/artifacts"
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
	// CodeBannerTimeout: the TCP connection was accepted but no SSH version
	// line came within the handshake timeout. CodeHandshakeTimeout: the
	// version line came, key exchange or login did not finish in time.
	// CodeClosedBeforeBanner: the server closed the connection before its
	// version line without saying anything (sshd's MaxStartups drop, a
	// forwarder that could not reach the host). All three happen before
	// anything ran on the server.
	CodeBannerTimeout      = "ssh_banner_timeout"
	CodeHandshakeTimeout   = "ssh_handshake_timeout"
	CodeClosedBeforeBanner = "ssh_closed_before_banner"
	// CodeRunTimeout: the remote command was started and did not finish in
	// time; CodeRunInterrupted: the connection was lost while it ran (no
	// exit status came back). In both cases the outcome is unknown.
	CodeRunTimeout     = "run_timeout"
	CodeRunInterrupted = "run_interrupted"
	// CodeJumpRefused: the relay of a jump channel refused to open the
	// forwarded connection (AllowTcpForwarding no or similar).
	CodeJumpRefused = "jump_forward_refused"
	// CodeChannelNotAllowed: the server's management channel cannot be used
	// (the jump server is not a managed relay, or the relay itself is not
	// reached directly).
	CodeChannelNotAllowed = "channel_not_allowed"
)

// Error is every error this package returns. Msg is scrubbed of the
// credential's secrets.
type Error struct {
	Code string
	Msg  string
	// RetryAfter (seconds) is set with CodeRateLimited: how long the panel
	// will not connect to the endpoint again.
	RetryAfter int
	// Offered (auth_failed / auth_method_unavailable) are the login methods
	// the server offered, as far as the handshake learned them ("password",
	// "publickey", "keyboard-interactive"). The panel only suggests a key
	// login when "publickey" is among them.
	Offered []string
	// NotExecuted: the failure happened before any command was started on
	// the server (connect, banner, handshake, login, host key, or the
	// relay hop of a jump). SafeToRetry: in addition the failure is of a
	// transient kind (connect timeout, banner or handshake timeout, refused
	// or closed before the handshake, rate limited after RetryAfter), so a
	// new attempt cannot repeat or half-repeat anything. The panel never
	// retries by itself; it only says so.
	NotExecuted bool
	SafeToRetry bool
	// Hop is "relay" when the failure is on the relay of a jump channel.
	Hop string
}

func (e *Error) Error() string { return e.Msg }

// notExecuted marks e as a failure before anything ran (retry: and of a
// transient kind).
func notExecuted(e *Error, retry bool) *Error {
	e.NotExecuted = true
	e.SafeToRetry = e.SafeToRetry || retry
	return e
}

// retryNote is appended to the message of a transient failure before
// execution.
const retryNote = "。面板还没有在这台服务器上执行任何操作，可以安全重试（面板不会自动重试）"

// NotExecutedOf / SafeToRetryOf read the flags of an *Error (false
// otherwise: an error that is not ours says nothing about what ran).
func NotExecutedOf(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.NotExecuted
}

func SafeToRetryOf(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.SafeToRetry
}

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

// OfferedOf returns the Offered methods of an *Error (or nil).
func OfferedOf(err error) []string {
	var e *Error
	if errors.As(err, &e) {
		return append([]string(nil), e.Offered...)
	}
	return nil
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
	// JumpPolicy, when set, is asked before a jump channel is used: it
	// returns an error when via may not serve as a jump host for target
	// (the API allows only servers of managed relay nodes).
	JumpPolicy func(via, target model.Server) error
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
	// Channel is the management channel used (direct | tunnel | jump).
	Channel string
	// Markers are the lines of the command's standard output that start
	// with "MERIDIAN_", in order (at most maxMarkers). They are collected
	// from stdout alone, line by line, so they are never split or glued by
	// standard error interleaving and never lost when Output is capped.
	Markers []string
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

// dialTCP opens the TCP connection of a direct or tunnel channel.
func (c *Connector) dialTCP(ctx context.Context, addr, note string) (net.Conn, error) {
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
			return nil, notExecuted(errf(CodeTimeout, "连接 %s 超时%s%s", addr, note, retryNote), true)
		}
		return nil, notExecuted(errf(CodeUnreachable, "无法连接 %s：%s%s", addr, plainNetErr(err), note), false)
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
	p, err := c.pathOf(sv)
	if err != nil {
		return Discovery{}, err
	}
	ep := p.cool
	if left := c.Pool.cooling(ep); left > 0 {
		return Discovery{}, rateLimitedErr(sv.Name, p.desc, left)
	}
	raw, relay, err := c.openPath(ctx, p, sv.Name)
	if err != nil {
		return Discovery{}, err
	}
	defer relay.close()
	conn := newBannerConn(raw)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.handshakeTimeout()))
	wd := newWatchdog(c.handshakeTimeout(), conn)
	defer wd.stop()
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
	sc, chans, reqs, herr := ssh.NewClientConn(conn, p.dial, cfg)
	wd.stop()
	if herr == nil {
		// Cannot happen without auth methods; close defensively.
		ssh.NewClient(sc, chans, reqs).Close()
	}
	if seen == nil {
		pre, sawSSH := conn.preBanner()
		if !sawSSH && rateLimitLine(pre) {
			c.Pool.rateLimited(ep)
			return Discovery{}, rateLimitedErr(sv.Name, p.desc, c.Pool.cooldown())
		}
		if herr != nil && (wd.fired() || isTimeout(herr)) {
			return Discovery{}, timeoutErr(sv.Name, sawSSH, p.note())
		}
		if herr != nil && !sawSSH && pre == "" && closedEarly(herr) {
			return Discovery{}, closedBeforeBannerErr(sv.Name, p.note())
		}
		return Discovery{}, notExecuted(errf(CodeNotSSH, "%s 没有完成 SSH 密钥交换，读不到主机公钥%s%s", p.desc, preBannerNote(pre, sawSSH), p.note()), false)
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

// session is one authenticated connection. relay is the relay's own
// session of a jump channel: it carries the forwarded TCP connection and
// lives exactly as long as client.
type session struct {
	client  *ssh.Client
	relay   *session
	method  string
	fp      string
	secrets []string
	credID  string
	created time.Time
}

// close closes the connection and, for a jump, the relay connection under
// it. Safe on nil.
func (s *session) close() {
	if s == nil {
		return
	}
	if s.client != nil {
		s.client.Close()
	}
	s.relay.close()
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
	path   path
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
	p, err := c.pathOf(sv)
	if err != nil {
		return resolved{}, err
	}
	k := poolKey{ServerID: sv.ID, Address: sv.Address, Port: sv.Port, User: sv.User,
		Fingerprint: sv.HostKey.Fingerprint, KeyType: sv.HostKey.KeyType, PinnedAt: sv.HostKey.PinnedAt, CredentialID: credID, CredentialGn: gen,
		Channel: p.mode, Dial: p.dial, Cool: p.cool}
	if p.via != nil {
		vk := p.via.key
		k.ViaID, k.ViaCred, k.ViaCool = vk.ServerID, vk.CredentialID, vk.Cool
		k.ViaKey = fmt.Sprintf("%+v", vk)
	}
	return resolved{t: t, sv: sv, credID: credID, meta: meta, key: k, path: p}, nil
}

// handshake dials the resolved target and authenticates.
func (c *Connector) handshake(ctx context.Context, r resolved) (*session, error) {
	t, sv, credID, meta := r.t, r.sv, r.credID, r.meta
	ep := r.path.cool
	if left := c.Pool.cooling(ep); left > 0 {
		return nil, rateLimitedErr(sv.Name, r.path.desc, left)
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
	raw, relay, err := c.openPath(ctx, r.path, sv.Name)
	if err != nil {
		return nil, err
	}
	conn := newBannerConn(raw)
	_ = conn.SetDeadline(time.Now().Add(c.handshakeTimeout()))
	// A forwarded connection (jump) has no deadlines: the watchdog closes
	// any connection whose handshake outlives the timeout.
	wd := newWatchdog(c.handshakeTimeout(), conn)
	sc, chans, reqs, err := ssh.NewClientConn(conn, r.path.dial, cfg)
	wd.stop()
	if err != nil {
		conn.Close()
		relay.close()
		pre, sawSSH := conn.preBanner()
		switch {
		case hostErr != nil:
			return nil, notExecuted(hostErr.(*Error), false)
		case !sawSSH && rateLimitLine(pre):
			// Refused before the version exchange: no key was seen, no
			// credential was read or sent.
			c.Pool.rateLimited(ep)
			return nil, rateLimitedErr(sv.Name, r.path.desc, c.Pool.cooldown())
		case authErr != nil:
			return nil, notExecuted(errf(CodeAuthFailed, "%s", credentials.Scrub(authErr.Error(), s.secrets...)), false)
		case errors.Is(err, errProbeOnly) || strings.Contains(err.Error(), "unable to authenticate"):
			authMu.Lock()
			used, others := tried, append([]string(nil), offered...)
			authMu.Unlock()
			if !used {
				e := errf(CodeAuthMethodUnavailable, "%s", methodUnavailableMsg(sv.Name, s.method, others))
				e.Offered = others
				return nil, notExecuted(e, false)
			}
			own := "publickey"
			if s.method == AuthPassword {
				own = "password"
			}
			e := errf(CodeAuthFailed, "%s 拒绝了 %s 的%s登录（服务器接受%s登录，但这份凭据没有通过）", sv.Name, sv.User, methodName(s.method), methodName(s.method))
			e.Offered = append([]string{own}, others...)
			return nil, notExecuted(e, false)
		case wd.fired() || isTimeout(err):
			return nil, timeoutErr(sv.Name, sawSSH, r.path.note())
		case !sawSSH && pre == "" && closedEarly(err):
			return nil, closedBeforeBannerErr(sv.Name, r.path.note())
		default:
			return nil, notExecuted(errf(CodeUnreachable, "%s 的 SSH 握手失败：%s%s%s", sv.Name, credentials.Scrub(err.Error(), s.secrets...), preBannerNote(credentials.Scrub(pre, s.secrets...), sawSSH), r.path.note()), false)
		}
	}
	conn.stop()
	_ = conn.SetDeadline(time.Time{})
	s.client = ssh.NewClient(sc, chans, reqs)
	s.relay = relay
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

// capWriter keeps the first n bytes of the combined output. Standard
// output and standard error are copied by two goroutines, so it is locked.
type capWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	n   int
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.n - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

func (w *capWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// maxMarkers bounds Result.Markers; maxMarkerLine bounds one marker line.
const (
	maxMarkers    = 512
	maxMarkerLine = 4096
)

// markerWriter collects the "MERIDIAN_" lines of standard output. It sees
// only stdout, so a line is assembled from consecutive stdout bytes even
// when the transport splits it and stderr arrives in between.
type markerWriter struct {
	mu      sync.Mutex
	line    []byte
	over    bool
	markers []string
}

func (w *markerWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range p {
		if b == '\n' {
			w.flush()
			continue
		}
		if len(w.line) < maxMarkerLine {
			w.line = append(w.line, b)
		} else {
			w.over = true
		}
	}
	return len(p), nil
}

func (w *markerWriter) flush() {
	l := strings.TrimSpace(string(w.line))
	if !w.over && strings.HasPrefix(l, "MERIDIAN_") && len(w.markers) < maxMarkers {
		w.markers = append(w.markers, l)
	}
	w.line, w.over = w.line[:0], false
}

func (w *markerWriter) result() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.line) > 0 {
		w.flush()
	}
	return append([]string(nil), w.markers...)
}

// run executes command (with stdin) on an authenticated session: a pooled
// connection of exactly this identity when the Connector has a Pool and one
// is idle (and fresh is false), else a new one. On success the connection
// goes back to the pool; after any error it is closed.
func (c *Connector) run(ctx context.Context, t Target, command string, stdin io.Reader) (res Result, err error) {
	return c.runOn(ctx, t, command, stdin, false, nil)
}

// followUp is a fixed, read-only command run on the same login right after
// the main command finished (with any exit status), before the connection
// is pooled or closed. It is not run when the main command's outcome is
// unknown (timeout, connection lost).
type followUp struct {
	command string
	max     int
	out     string
	ok      bool
}

func (c *Connector) runOn(ctx context.Context, t Target, command string, stdin io.Reader, fresh bool, after *followUp) (res Result, err error) {
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
			return Result{ServerID: t.ServerID, Channel: r.path.mode}, err
		}
	}
	defer func() {
		if err == nil && c.Pool != nil && ctx.Err() == nil {
			c.Pool.put(r.key, s)
			return
		}
		s.close()
	}()
	res = Result{AuthMethod: s.method, Fingerprint: s.fp, ServerID: t.ServerID, CredentialID: s.credID, Reused: reused, Channel: r.path.mode}
	sess, err := s.client.NewSession()
	if err != nil {
		// No channel, nothing started.
		return res, notExecuted(errf(CodeCommandFailed, "打开 SSH 会话失败：%s", credentials.Scrub(err.Error(), s.secrets...)), false)
	}
	defer sess.Close()
	max := c.MaxOutput
	if max <= 0 {
		max = 1 << 20
	}
	out := &capWriter{n: max}
	marks := &markerWriter{}
	sess.Stdout, sess.Stderr = io.MultiWriter(out, marks), out
	if stdin != nil {
		sess.Stdin = stdin
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		s.close()
		res.Output = credentials.Scrub(out.String(), s.secrets...)
		res.Markers = scrubAll(marks.result(), s.secrets)
		return res, errf(CodeRunTimeout, "远程执行超时（%v）：命令已经开始执行，结果不明", ctx.Err())
	}
	res.Output = credentials.Scrub(out.String(), s.secrets...)
	res.Markers = scrubAll(marks.result(), s.secrets)
	var exit *ssh.ExitError
	finished := err == nil || errors.As(err, &exit)
	if after != nil && finished && ctx.Err() == nil {
		after.out, after.ok = c.followOn(ctx, s, after)
	}
	if err != nil {
		if !finished {
			// No exit status: the connection or the session went away while
			// the command ran.
			return res, errf(CodeRunInterrupted, "远程执行中断（没有收到退出状态）：%s；结果不明", credentials.Scrub(err.Error(), s.secrets...))
		}
		return res, errf(CodeCommandFailed, "远程执行失败：%s", credentials.Scrub(err.Error(), s.secrets...))
	}
	return res, nil
}

// followOn runs a follow-up's fixed command in a new session of s.
func (c *Connector) followOn(ctx context.Context, s *session, f *followUp) (string, bool) {
	fctx, cancel := context.WithTimeout(ctx, FollowUpTimeout)
	defer cancel()
	sess, err := s.client.NewSession()
	if err != nil {
		return "", false
	}
	defer sess.Close()
	out := &capWriter{n: f.max}
	sess.Stdout = out
	done := make(chan error, 1)
	go func() { done <- sess.Run(f.command) }()
	select {
	case err = <-done:
	case <-fctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		return "", false
	}
	return credentials.Scrub(out.String(), s.secrets...), err == nil
}

// FollowUpTimeout bounds a follow-up read.
const FollowUpTimeout = 30 * time.Second

func scrubAll(in []string, secrets []string) []string {
	for i := range in {
		in[i] = credentials.Scrub(in[i], secrets...)
	}
	return in
}

// RunScript sends a panel-built script to "bash -s" on stdin, so nothing
// in it (a WireGuard private key, a Mesh node token) appears in the remote
// process list.
func (c *Connector) RunScript(ctx context.Context, t Target, script string) (Result, error) {
	return c.run(ctx, t, "bash -s", strings.NewReader(script))
}

// NodeStateCommand is the fixed, read-only command that reads a remote
// node's provision record: the journal (state, node, deployment, run,
// leftovers) and the header of the ownership manifest (node, deployment,
// server, bundle, installed). It takes no input and changes nothing.
const NodeStateCommand = `{ printf 'meridian-node-state 1\n'; if [ -f /var/lib/meridian/node/journal ]; then head -c 16384 /var/lib/meridian/node/journal | head -n 200 | sed 's/^/journal /'; fi; if [ -f /var/lib/meridian/node/manifest ]; then grep -E '^(node|deployment|server|bundle|installed) ' /var/lib/meridian/node/manifest | head -n 16 | sed 's/^/manifest /'; fi; echo meridian-node-state-end; } 2>/dev/null | head -c 32769`

// NodeStateMax is the largest accepted answer of NodeStateCommand.
const NodeStateMax = 32 << 10

// RunScriptAndRead sends a panel-built script like RunScript and, when the
// script finished (exit status received, success or failure) on a live
// connection, reads NodeStateCommand on the same login before the
// connection is pooled or closed: no second connection, and the host's own
// record of what the run did (committed, compensated, incomplete) even when
// the script's markers did not reach the panel. state is "" with ok false
// when it was not read (the script's outcome is then unknown, or the read
// failed).
func (c *Connector) RunScriptAndRead(ctx context.Context, t Target, script string) (res Result, state string, ok bool, err error) {
	f := &followUp{command: NodeStateCommand, max: NodeStateMax + 1}
	res, err = c.runOn(ctx, t, "bash -s", strings.NewReader(script), false, f)
	return res, f.out, f.ok, err
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
	res, err := c.runOn(ctx, Target{ServerID: serverID}, TestCommand, nil, true, nil)
	ct := model.ConnectionTest{AuthMethod: res.AuthMethod, DurationMS: time.Since(start).Milliseconds()}
	if res.Channel != model.ChannelDirect {
		ct.Channel = res.Channel
	}
	if err != nil {
		switch CodeOf(err) {
		case CodeNotFound, CodeUntrusted, CodeNoCredential:
			return ct, err
		}
		ct.Code, ct.Error, ct.RetryAfter, ct.Offered = CodeOf(err), err.Error(), RetryAfterOf(err), OfferedOf(err)
		ct.NotExecuted, ct.SafeToRetry = NotExecutedOf(err), SafeToRetryOf(err)
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

// checkPreflightArgs is the second check of the preflight command's
// arguments (preflight.ArgsWithProbes is the first): single-quoted absolute
// paths and single-quoted TCP connect probes, nothing else.
func checkPreflightArgs(args []string) error {
	if len(args) > preflight.MaxPaths+preflight.MaxProbes {
		return errf(CodeBadArgs, "预检参数过多")
	}
	probes := 0
	for _, a := range args {
		// A TCP connect probe for an external exit's proxy
		// ('tcp4:<IPv4>:<port>', preflight.ValidProbe): the carrier's
		// preflight was refused here on a real host because only paths
		// were accepted.
		if q := strings.TrimSuffix(strings.TrimPrefix(a, "'"), "'"); len(q)+2 == len(a) && preflight.ValidProbe(q) {
			if probes++; probes > preflight.MaxProbes {
				return errf(CodeBadArgs, "预检参数过多")
			}
			continue
		}
		if !preflightArg.MatchString(a) || strings.Contains(a, "..") {
			return errf(CodeBadArgs, "预检参数不合法：%q", a)
		}
	}
	if len(args)-probes > preflight.MaxPaths {
		return errf(CodeBadArgs, "预检参数过多")
	}
	return nil
}

// RunPreflight sends the fixed read-only preflight script to "bash -s --
// <paths>" on the target (trusted, pinned host key; t pins the identity
// the caller captured) and returns its report, capped at
// preflight.MaxReport+1 bytes so an oversized answer is recognisable. The
// script text is preflight.Script(); args come from preflight.Args and are
// checked again here.
func (c *Connector) RunPreflight(ctx context.Context, t Target, args []string) (Result, error) {
	if err := checkPreflightArgs(args); err != nil {
		return Result{ServerID: t.ServerID}, err
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

// StageTimeout bounds one binary transfer (connect, login, send, verify).
const StageTimeout = 5 * time.Minute

// CodeStageFailed: a panel-delivered binary could not be staged on the
// host (refused arguments, short write, digest mismatch on the host).
const CodeStageFailed = "artifact_stage_failed"

// StageCommand is the fixed receive command for a panel-delivered binary:
// it reads exactly size bytes from stdin into artifacts.StagePath(name)+".part"
// (mode 0600, directory 0700), checks the size and the SHA-256 on the host
// and only then renames it to artifacts.StagePath(name); anything else
// removes the partial file. Only name (wstunnel | smartdns), sum (64 hex)
// and size (1 … artifacts.MaxSize) vary, all validated before the command
// is built; nothing else of a request reaches it. It installs nothing:
// the provision script verifies the staged file again and installs it
// inside its transaction.
func StageCommand(name, sum string, size int64) (string, error) {
	if !artifacts.ValidName(name) || !artifacts.ValidSHA256(sum) || size <= 0 || size > artifacts.MaxSize {
		return "", errf(CodeBadArgs, "二进制传输参数不合法")
	}
	f := artifacts.StagePath(name)
	return fmt.Sprintf(`umask 077; d='%s'; f='%s'; mkdir -p "$d" && chmod 700 "$d" && head -c %d > "$f.part" && [ "$(wc -c < "$f.part" | tr -d ' ')" = %d ] && [ "$(sha256sum "$f.part" | cut -c1-64)" = %s ] && mv -f "$f.part" "$f" && echo 'MERIDIAN_STAGED %s' || { rm -f "$f.part"; echo MERIDIAN_STAGE_FAILED; exit 1; }`,
		artifacts.StageDir, f, size, size, sum, sum), nil
}

// Stage sends a panel-delivered binary to the target over the pooled,
// authenticated connection (the same login as the preflight re-run and the
// provision script of the flow) with StageCommand. data is checked against
// sum before anything is sent; the host checks it again.
func (c *Connector) Stage(ctx context.Context, t Target, name, sum string, data []byte) (Result, error) {
	cmd, err := StageCommand(name, sum, int64(len(data)))
	if err != nil {
		return Result{ServerID: t.ServerID}, err
	}
	if artifacts.SHA256Of(data) != sum {
		return Result{ServerID: t.ServerID}, errf(CodeStageFailed, "%s 的内容与固定摘要不一致，没有发送", name)
	}
	ctx, cancel := context.WithTimeout(ctx, StageTimeout)
	defer cancel()
	cc := *c
	cc.MaxOutput = 4 << 10
	res, err := cc.run(ctx, t, cmd, bytes.NewReader(data))
	if err != nil {
		if CodeOf(err) == CodeCommandFailed {
			return res, errf(CodeStageFailed, "主机上没能暂存 %s（大小或 SHA-256 校验没有通过，或磁盘已满）：%s", name, strings.TrimSpace(res.Output))
		}
		return res, err
	}
	if !strings.Contains(res.Output, "MERIDIAN_STAGED "+sum) {
		return res, errf(CodeStageFailed, "主机没有确认暂存 %s", name)
	}
	return res, nil
}

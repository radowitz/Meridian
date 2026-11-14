package sshexec

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// What a server sent before its SSH version line.
//
// RFC 4253 lets a server send text lines before "SSH-2.0-…". OpenSSH uses
// that for exactly one refusal that matters here: with PerSourcePenalties
// (OpenSSH 9.8 and later, on by default) a source address that recently
// caused failed or unauthenticated connections is answered with the single
// line "Not allowed at this time" and the connection is closed, before any
// key exchange. golang.org/x/crypto/ssh skips such lines and then reports
// only EOF. bannerConn keeps the first bytes the server sent so a failed
// handshake can say what the server actually answered. Nothing the client
// sends is recorded, and the capture stops after the handshake (the bytes
// before it are the version exchange and the plaintext key-exchange init,
// never credential material).

const bannerCap = 512

type bannerConn struct {
	net.Conn
	mu   sync.Mutex
	buf  []byte
	done bool
}

func newBannerConn(c net.Conn) *bannerConn { return &bannerConn{Conn: c} }

func (c *bannerConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if !c.done {
			if room := bannerCap - len(c.buf); room > 0 {
				if n < room {
					room = n
				}
				c.buf = append(c.buf, p[:room]...)
			}
			if len(c.buf) >= bannerCap {
				c.done = true
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

// stop ends the capture and drops what was kept.
func (c *bannerConn) stop() {
	c.mu.Lock()
	c.done, c.buf = true, nil
	c.mu.Unlock()
}

// preBanner returns the printable text of the lines the server sent before
// its "SSH-" version line (capped at 200 characters), and whether a version
// line was seen at all.
func (c *bannerConn) preBanner() (string, bool) {
	c.mu.Lock()
	raw := string(c.buf)
	c.mu.Unlock()
	var lines []string
	sawSSH := false
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.HasPrefix(l, "SSH-") {
			sawSSH = true
			break
		}
		if t := clean(l); t != "" {
			lines = append(lines, t)
		}
	}
	out := strings.Join(lines, " / ")
	if r := []rune(out); len(r) > 200 {
		out = string(r[:200]) + "…"
	}
	return out, sawSSH
}

// rateLimitLine: the pre-banner text is OpenSSH's per-source refusal.
func rateLimitLine(pre string) bool {
	return strings.Contains(strings.ToLower(pre), "not allowed at this time")
}

// DefaultCooldown is how long the panel stays away from an SSH endpoint
// after it answered "Not allowed at this time" (when no Pool sets another
// value). OpenSSH's penalties start at 15 s and accumulate up to 10 minutes
// (PerSourcePenalties defaults), so a minute is a floor, not a promise.
const DefaultCooldown = 60 * time.Second

func rateLimitedErr(name, addr string, retry time.Duration) *Error {
	secs := int(retry.Round(time.Second) / time.Second)
	if secs < 1 {
		secs = 1
	}
	// Refused before the version exchange: nothing was authenticated or run,
	// and after RetryAfter a new attempt is safe.
	return &Error{Code: CodeRateLimited, RetryAfter: secs, NotExecuted: true, SafeToRetry: true, Msg: fmt.Sprintf(
		"%s（%s）暂时拒绝来自面板这个来源地址的连接：SSH 握手之前它只回了一行「Not allowed at this time」就断开了。"+
			"这是 OpenSSH 的按来源限速（PerSourcePenalties）：短时间内来自同一地址的连接太多，或有连接没有完成登录（例如只读取主机指纹、端口扫描），都会让它暂时拒绝这个地址；经端口转发到达的服务器上，所有连接都来自转发器的同一个地址。"+
			"这不是密码、密钥或主机指纹的问题，面板没有尝试登录。等一会儿再试：面板在 %d 秒内不会再连接这台服务器，之后仍被拒绝时再多等几分钟（限速时间会累积，最长约 10 分钟）。",
		name, addr, secs)}
}

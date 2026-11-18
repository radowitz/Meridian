package sshexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/radowitz/meridian/internal/model"
)

// Management channels (model.ManagementChannel).
//
// A server is reached on one path, chosen explicitly by the operator:
//
//   - direct: TCP from the panel to the server's address and port;
//   - tunnel: TCP from the panel to an address it reaches through an
//     already established tunnel (the server's tunnel address);
//   - jump:   an authenticated SSH connection to a managed relay (that
//     relay's own stored credential, its own pinned host key; it must be
//     reached directly), a direct-tcpip channel from the relay to the
//     server, and the server's SSH session inside that channel.
//
// Whatever the path, the server's own handshake is done by the panel with
// the server's pinned key and stored credential: the relay only forwards
// encrypted bytes. No agent is forwarded (the client never requests agent
// forwarding), no key or password of either hop leaves the panel, and the
// relay runs nothing. A channel that does not work is reported as such;
// the panel never falls back to another path by itself.

// path is how one resolved target is reached.
type path struct {
	mode string // direct | tunnel | jump
	// dial is the host:port dialed (direct, tunnel) or forwarded to by the
	// relay (jump).
	dial string
	// cool is the cooldown key: the sshd behind dial sees the panel (direct,
	// tunnel) or the relay (jump) as source.
	cool string
	// desc names the path in messages.
	desc string
	// via is the relay of a jump, resolved like any target.
	via *resolved
}

// note is the channel remark added to connection-class errors.
func (p path) note() string {
	switch p.mode {
	case model.ChannelTunnel:
		return fmt.Sprintf("（管理通道：经隧道地址 %s；面板不会自动改走直连或别的通道，通道不通时可在服务器页改选管理通道）", p.dial)
	case model.ChannelJump:
		return fmt.Sprintf("（管理通道：%s；面板不会自动改走直连或别的通道，通道不通时可在服务器页改选管理通道）", p.desc)
	}
	return ""
}

// pathOf resolves sv's management channel. A jump resolves its relay as a
// target of its own (trusted key and credential required) and refuses a
// relay that is itself not reached directly, or one the policy rejects.
func (c *Connector) pathOf(sv model.Server) (path, error) {
	ch := sv.Channel
	port := sv.Port
	if ch != nil && ch.Port != 0 {
		port = ch.Port
	}
	switch ch.ChannelMode() {
	case model.ChannelDirect:
		ep := endpoint(sv.Address, sv.Port)
		return path{mode: model.ChannelDirect, dial: ep, cool: ep, desc: ep}, nil
	case model.ChannelTunnel:
		if ch.Address == "" {
			return path{}, notExecuted(errf(CodeChannelNotAllowed, "服务器 %s 的管理通道（隧道地址）没有填写地址", sv.Name), false)
		}
		ep := endpoint(ch.Address, port)
		return path{mode: model.ChannelTunnel, dial: ep, cool: ep, desc: "隧道地址 " + ep}, nil
	case model.ChannelJump:
		via, err := c.Store.Server(ch.ViaServerID)
		if err != nil {
			return path{}, notExecuted(errf(CodeChannelNotAllowed, "服务器 %s 的跳转中继 %s 不存在", sv.Name, ch.ViaServerID), false)
		}
		if via.ID == sv.ID || via.Channel.ChannelMode() != model.ChannelDirect {
			return path{}, notExecuted(errf(CodeChannelNotAllowed, "服务器 %s 的跳转中继 %s 自己不是直连的：只支持一跳", sv.Name, via.Name), false)
		}
		if c.JumpPolicy != nil {
			if err := c.JumpPolicy(via, sv); err != nil {
				return path{}, notExecuted(errf(CodeChannelNotAllowed, "%s", err.Error()), false)
			}
		}
		r, err := c.resolve(Target{ServerID: via.ID})
		if err != nil {
			return path{}, relayErr(sv.Name, via.Name, err)
		}
		addr := sv.Address
		if ch.Address != "" {
			addr = ch.Address
		}
		ep := endpoint(addr, port)
		return path{mode: model.ChannelJump, dial: ep, cool: "via " + via.ID + " " + ep,
			desc: fmt.Sprintf("经中继 %s 跳转到 %s", via.Name, ep), via: &r}, nil
	}
	return path{}, notExecuted(errf(CodeChannelNotAllowed, "服务器 %s 的管理通道 %q 不认识", sv.Name, ch.Mode), false)
}

// openPath opens the byte stream to the server's sshd. For a jump it
// returns the relay session too; the caller closes it with the stream.
func (c *Connector) openPath(ctx context.Context, p path, name string) (net.Conn, *session, error) {
	if p.mode != model.ChannelJump {
		conn, err := c.dialTCP(ctx, p.dial, p.note())
		return conn, nil, err
	}
	relay, err := c.handshake(ctx, *p.via)
	if err != nil {
		return nil, nil, relayErr(name, p.via.sv.Name, err)
	}
	dctx, cancel := context.WithTimeout(ctx, c.dialTimeout())
	defer cancel()
	conn, err := relay.client.DialContext(dctx, "tcp", p.dial)
	if err != nil {
		relay.close()
		var oce *ssh.OpenChannelError
		switch {
		case errors.As(err, &oce) && oce.Reason == ssh.Prohibited:
			return nil, nil, notExecuted(errf(CodeJumpRefused, "中继 %s 拒绝转发到 %s（它的 sshd 不允许 TCP 转发：AllowTcpForwarding / PermitOpen）%s", p.via.sv.Name, p.dial, p.note()), false)
		case errors.As(err, &oce):
			return nil, nil, notExecuted(errf(CodeUnreachable, "中继 %s 连不上 %s：%s%s", p.via.sv.Name, p.dial, oce.Message, p.note()), false)
		case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
			return nil, nil, notExecuted(errf(CodeTimeout, "中继 %s 转发到 %s 超时%s%s", p.via.sv.Name, p.dial, p.note(), retryNote), true)
		default:
			return nil, nil, notExecuted(errf(CodeUnreachable, "经中继 %s 打开到 %s 的转发失败：%s%s", p.via.sv.Name, p.dial, err.Error(), p.note()), false)
		}
	}
	return conn, relay, nil
}

// relayErr labels an error of a jump's first hop. Nothing reached the
// target, so nothing ran there.
func relayErr(target, relay string, err error) error {
	var e *Error
	if !errors.As(err, &e) {
		return err
	}
	out := *e
	out.Hop = "relay"
	out.NotExecuted = true
	out.Msg = fmt.Sprintf("经中继 %s 跳转到 %s 的第一跳失败（没有连到 %s，也没有在它上面执行任何操作）：%s", relay, target, target, e.Msg)
	return &out
}

// timeoutErr classifies a handshake that did not finish in time: without
// the server's version line it is a banner timeout, with it a handshake
// timeout. Both before anything ran.
func timeoutErr(name string, sawSSH bool, note string) *Error {
	if !sawSSH {
		return notExecuted(errf(CodeBannerTimeout, "%s 接受了 TCP 连接，但在超时之前没有发出 SSH 版本行%s%s", name, note, retryNote), true)
	}
	return notExecuted(errf(CodeHandshakeTimeout, "%s 的 SSH 握手（密钥交换或登录）超时%s%s", name, note, retryNote), true)
}

// closedBeforeBannerErr: the server closed the connection before its
// version line without a word (sshd MaxStartups, a forwarder whose target
// is down).
func closedBeforeBannerErr(name, note string) *Error {
	return notExecuted(errf(CodeClosedBeforeBanner, "%s 在 SSH 版本行之前就关闭了连接（sshd 的并发连接上限 MaxStartups、限速，或端口转发后面的主机不可达）%s%s", name, note, retryNote), true)
}

// closedEarly: the handshake ended because the peer closed the stream.
func closedEarly(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "connection reset by peer")
}

// watchdog closes a connection whose handshake outlives its timeout (a
// forwarded connection has no deadlines of its own).
type watchdog struct {
	t    *time.Timer
	hit  atomic.Bool
	once sync.Once
}

func newWatchdog(d time.Duration, c io.Closer) *watchdog {
	w := &watchdog{}
	w.t = time.AfterFunc(d, func() {
		w.hit.Store(true)
		c.Close()
	})
	return w
}

func (w *watchdog) stop()       { w.once.Do(func() { w.t.Stop() }) }
func (w *watchdog) fired() bool { return w.hit.Load() }

// Package sshtest is an in-process SSH server on 127.0.0.1 for tests of
// the SSH path (password and public-key authentication, host keys). It is
// imported only by tests; it never listens on anything but loopback.
package sshtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Server is a minimal SSH server: exec requests only.
type Server struct {
	Host string
	Port int

	mu       sync.Mutex
	signer   ssh.Signer
	password string
	authKey  ssh.PublicKey
	// offer limits the advertised methods ("password", "publickey"); nil
	// offers both.
	offer []string
	// AuthAttempts counts password and public-key attempts (any outcome).
	authAttempts int
	commands     []string
	stdins       []string
	handler      func(cmd, stdin string) (string, uint32)
	// stream, when set, answers exec requests instead of handler, writing
	// standard output and standard error itself (interleaving tests).
	stream func(cmd, stdin string, stdout, stderr io.Writer) uint32
	// forward allows direct-tcpip channels (a relay for jump tests): only
	// to 127.0.0.1, recorded in forwards.
	forward  bool
	forwards []string
	// requests records every channel and request type a client asked for
	// (to prove, for example, that no agent forwarding was requested).
	requests []string
	// silent: accept TCP and never answer (banner timeout); stall: send the
	// version line and then nothing (handshake timeout); hangup: close
	// before the version line without a word.
	silent, stall, hangup bool
	// refuse, when set, is written to every new connection before the SSH
	// version line, and the connection is closed (OpenSSH's
	// PerSourcePenalties answer: "Not allowed at this time").
	refuse string
	// accepted counts TCP connections; logins counts authenticated SSH
	// connections.
	accepted int
	logins   int
	conns    map[net.Conn]struct{}
	stopped  bool

	l     net.Listener
	wg    sync.WaitGroup
	close sync.Once
}

// NewHostKey returns a fresh ed25519 host key signer.
func NewHostKey() ssh.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		panic(err)
	}
	return s
}

// Start listens on 127.0.0.1 with a new host key.
func Start() (*Server, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{l: l, signer: NewHostKey()}
	a := l.Addr().(*net.TCPAddr)
	s.Host, s.Port = "127.0.0.1", a.Port
	s.handler = func(cmd, stdin string) (string, uint32) { return "", 0 }
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Close stops the server (idempotent). Open connections, including ones a
// client keeps for reuse, are closed.
func (s *Server) Close() {
	s.close.Do(func() {
		s.l.Close()
		s.mu.Lock()
		s.stopped = true
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}

// RefuseBeforeBanner makes the server answer every new connection with
// line (plus CRLF) before any SSH version line and close it, like OpenSSH
// with PerSourcePenalties answering "Not allowed at this time". An empty
// line restores normal service.
func (s *Server) RefuseBeforeBanner(line string) { s.mu.Lock(); s.refuse = line; s.mu.Unlock() }

// AllowForwarding makes the server accept direct-tcpip channels to
// 127.0.0.1 (a relay in jump tests).
func (s *Server) AllowForwarding(on bool) { s.mu.Lock(); s.forward = on; s.mu.Unlock() }

// Forwards are the host:port targets of accepted direct-tcpip channels.
func (s *Server) Forwards() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.forwards...)
}

// Requests are the channel types and request types clients asked for.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// Silent makes the server accept connections and never send anything
// (an SSH banner timeout on the client).
func (s *Server) Silent(on bool) { s.mu.Lock(); s.silent = on; s.mu.Unlock() }

// Stall makes the server send its version line and then nothing (a
// handshake timeout on the client).
func (s *Server) Stall(on bool) { s.mu.Lock(); s.stall = on; s.mu.Unlock() }

// HangUp makes the server close every new connection before its version
// line without sending anything (sshd's MaxStartups drop).
func (s *Server) HangUp(on bool) { s.mu.Lock(); s.hangup = on; s.mu.Unlock() }

// SetStreamHandler answers exec requests by writing to stdout and stderr
// directly (nil restores SetHandler's answers).
func (s *Server) SetStreamHandler(h func(cmd, stdin string, stdout, stderr io.Writer) uint32) {
	s.mu.Lock()
	s.stream = h
	s.mu.Unlock()
}

// Accepted is the number of TCP connections accepted so far.
func (s *Server) Accepted() int { s.mu.Lock(); defer s.mu.Unlock(); return s.accepted }

// Logins is the number of connections that completed authentication.
func (s *Server) Logins() int { s.mu.Lock(); defer s.mu.Unlock(); return s.logins }

// Open is the number of connections currently open.
func (s *Server) Open() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.conns) }

// SetHostKey replaces the host key (a "reinstalled" host).
func (s *Server) SetHostKey(k ssh.Signer) { s.mu.Lock(); s.signer = k; s.mu.Unlock() }

// HostKey is the current host public key.
func (s *Server) HostKey() ssh.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signer.PublicKey()
}

// Fingerprint is ssh.FingerprintSHA256 of the current host key.
func (s *Server) Fingerprint() string { return ssh.FingerprintSHA256(s.HostKey()) }

// SetPassword accepts this password ("" disables password auth).
func (s *Server) SetPassword(p string) { s.mu.Lock(); s.password = p; s.mu.Unlock() }

// SetAuthorizedKey accepts this public key (nil disables key auth).
func (s *Server) SetAuthorizedKey(k ssh.PublicKey) { s.mu.Lock(); s.authKey = k; s.mu.Unlock() }

// SetHandler answers exec requests: output and exit status.
func (s *Server) SetHandler(h func(cmd, stdin string) (string, uint32)) {
	s.mu.Lock()
	s.handler = h
	s.mu.Unlock()
}

// OfferOnly makes the server advertise only these methods ("password",
// "publickey"), like sshd with PasswordAuthentication no. No arguments
// restores the default (both).
func (s *Server) OfferOnly(methods ...string) {
	s.mu.Lock()
	s.offer = append([]string(nil), methods...)
	if len(methods) == 0 {
		s.offer = nil
	}
	s.mu.Unlock()
}

// AuthAttempts is the number of authentication attempts so far.
func (s *Server) AuthAttempts() int { s.mu.Lock(); defer s.mu.Unlock(); return s.authAttempts }

// Commands and Stdins are the exec requests received.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func (s *Server) Stdins() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.stdins...)
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.l.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

func (s *Server) config() *ssh.ServerConfig {
	s.mu.Lock()
	signer := s.signer
	offer := s.offer
	s.mu.Unlock()
	offers := func(m string) bool {
		if offer == nil {
			return true
		}
		for _, o := range offer {
			if o == m {
				return true
			}
		}
		return false
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.authAttempts++
			if s.password != "" && string(pw) == s.password {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.authAttempts++
			if s.authKey != nil && bytes.Equal(k.Marshal(), s.authKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	if !offers("password") {
		cfg.PasswordCallback = nil
	}
	if !offers("publickey") {
		cfg.PublicKeyCallback = nil
	}
	cfg.AddHostKey(signer)
	return cfg
}

func (s *Server) handle(c net.Conn) {
	s.mu.Lock()
	s.accepted++
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	s.conns[c] = struct{}{}
	refuse, stopped := s.refuse, s.stopped
	silent, stall, hangup := s.silent, s.stall, s.hangup
	s.mu.Unlock()
	if stopped {
		c.Close()
	}
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		c.Close()
	}()
	if refuse != "" {
		_, _ = c.Write([]byte(refuse + "\r\n"))
		return
	}
	if hangup {
		return
	}
	if silent || stall {
		if stall {
			_, _ = c.Write([]byte("SSH-2.0-sshtest-stall\r\n"))
		}
		_, _ = io.Copy(io.Discard, c)
		return
	}
	conn, chans, reqs, err := ssh.NewServerConn(c, s.config())
	if err != nil {
		return
	}
	s.mu.Lock()
	s.logins++
	s.mu.Unlock()
	defer conn.Close()
	go func() {
		for r := range reqs {
			s.note("global " + r.Type)
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	for nc := range chans {
		s.note("channel " + nc.ChannelType())
		if nc.ChannelType() == "direct-tcpip" {
			s.forwardChannel(nc)
			continue
		}
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.session(ch, creqs)
	}
}

func (s *Server) note(what string) {
	s.mu.Lock()
	s.requests = append(s.requests, what)
	s.mu.Unlock()
}

// forwardChannel serves a direct-tcpip channel to 127.0.0.1 when allowed.
func (s *Server) forwardChannel(nc ssh.NewChannel) {
	var p struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	s.mu.Lock()
	allowed := s.forward
	s.mu.Unlock()
	if !allowed {
		_ = nc.Reject(ssh.Prohibited, "forwarding disabled")
		return
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil || p.Host != "127.0.0.1" {
		_ = nc.Reject(ssh.Prohibited, "loopback only")
		return
	}
	addr := net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
	up, err := net.Dial("tcp", addr)
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, creqs, err := nc.Accept()
	if err != nil {
		up.Close()
		return
	}
	s.mu.Lock()
	s.forwards = append(s.forwards, addr)
	s.mu.Unlock()
	go ssh.DiscardRequests(creqs)
	go func() {
		_, _ = io.Copy(up, ch)
		up.Close()
	}()
	go func() {
		_, _ = io.Copy(ch, up)
		ch.Close()
	}()
}

func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		s.note("request " + req.Type)
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(req.Type == "env", nil)
			}
			continue
		}
		var p struct{ Cmd string }
		if err := ssh.Unmarshal(req.Payload, &p); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		in, _ := io.ReadAll(ch)
		s.mu.Lock()
		s.commands = append(s.commands, p.Cmd)
		s.stdins = append(s.stdins, string(in))
		h, stream := s.handler, s.stream
		s.mu.Unlock()
		var code uint32
		if stream != nil {
			code = stream(p.Cmd, string(in), ch, ch.Stderr())
		} else {
			var out string
			out, code = h(p.Cmd, string(in))
			_, _ = ch.Write([]byte(out))
		}
		var st [4]byte
		binary.BigEndian.PutUint32(st[:], code)
		_, _ = ch.SendRequest("exit-status", false, st[:])
		return
	}
}

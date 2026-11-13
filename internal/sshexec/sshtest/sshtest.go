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
	conn, chans, reqs, err := ssh.NewServerConn(c, s.config())
	if err != nil {
		return
	}
	s.mu.Lock()
	s.logins++
	s.mu.Unlock()
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
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

func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
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
		h := s.handler
		s.mu.Unlock()
		out, code := h(p.Cmd, string(in))
		_, _ = ch.Write([]byte(out))
		var st [4]byte
		binary.BigEndian.PutUint32(st[:], code)
		_, _ = ch.SendRequest("exit-status", false, st[:])
		return
	}
}

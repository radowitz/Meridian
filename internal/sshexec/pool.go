package sshexec

import (
	"context"
	"sync"
	"time"
)

// Pool keeps authenticated SSH connections for reuse within one operation
// flow (the preflight re-run and the provision script of one request; the
// plan and the run of a withdrawal; the stages of a Mesh deployment; a
// connection test followed by a preflight) so a server that limits
// connections per source address sees one login instead of one per step.
//
// Reuse is bound to the full identity a connection was authenticated
// under: server ID, address, port, user, the trusted host-key fingerprint
// and key type, the SSH credential ID and the generation of its secret.
// Before every reuse that identity is resolved again from the credential
// store; any difference (the server was edited or deleted, the pin was
// re-trusted or cleared, the credential was replaced or its secret
// rotated) means the idle connection is closed, never used. A connection
// is also closed when it is older than MaxAge, idle longer than IdleTTL,
// when the operation that used it ended with any error, when its context
// was cancelled, and when it no longer answers a keepalive. The API layer
// additionally invalidates a server's or credential's connections on every
// edit (Invalidate*). A connection is lent to one operation at a time.
//
// Pool also remembers endpoints that answered "Not allowed at this time"
// and refuses to dial them again for Cooldown: no automatic retry, and no
// hammering by repeated clicks.
type Pool struct {
	// IdleTTL (default 60 s) and MaxAge (default 5 min) bound how long a
	// connection may be kept; Cooldown (default DefaultCooldown) how long a
	// rate-limited endpoint is left alone.
	IdleTTL  time.Duration
	MaxAge   time.Duration
	Cooldown time.Duration
	// Now is the clock (tests).
	Now func() time.Time

	mu   sync.Mutex
	idle map[poolKey]*pooled
	cool map[string]time.Time
}

// poolKey is the identity a connection is bound to.
type poolKey struct {
	ServerID     string
	Address      string
	Port         int
	User         string
	Fingerprint  string
	KeyType      string
	PinnedAt     string
	CredentialID string
	CredentialGn int
}

type pooled struct {
	s       *session
	key     poolKey
	created time.Time
	used    time.Time
	timer   *time.Timer
}

func (p *Pool) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Pool) idleTTL() time.Duration {
	if p.IdleTTL > 0 {
		return p.IdleTTL
	}
	return 60 * time.Second
}

func (p *Pool) maxAge() time.Duration {
	if p.MaxAge > 0 {
		return p.MaxAge
	}
	return 5 * time.Minute
}

func (p *Pool) cooldown() time.Duration {
	if p == nil || p.Cooldown <= 0 {
		return DefaultCooldown
	}
	return p.Cooldown
}

// cooling returns how much of an endpoint's cooldown is left (0 = none).
func (p *Pool) cooling(addr string) time.Duration {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	until, ok := p.cool[addr]
	if !ok {
		return 0
	}
	left := until.Sub(p.now())
	if left <= 0 {
		delete(p.cool, addr)
		return 0
	}
	return left
}

// rateLimited starts an endpoint's cooldown and closes its idle
// connections (they may be counted against the same source).
func (p *Pool) rateLimited(addr string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.cool == nil {
		p.cool = map[string]time.Time{}
	}
	p.cool[addr] = p.now().Add(p.cooldown())
	var drop []*pooled
	for k, e := range p.idle {
		if endpoint(k.Address, k.Port) == addr {
			drop = append(drop, e)
			delete(p.idle, k)
		}
	}
	p.mu.Unlock()
	closeAll(drop)
}

// CooldownLeft reports the cooldown left for a server's SSH endpoint.
func (p *Pool) CooldownLeft(address string, port int) time.Duration {
	return p.cooling(endpoint(address, port))
}

// take hands out the idle connection for exactly this identity, if a live
// one exists. Idle connections of the same server under another identity
// are closed on the way.
func (p *Pool) take(k poolKey) *session {
	if p == nil {
		return nil
	}
	now := p.now()
	p.mu.Lock()
	var drop []*pooled
	var got *pooled
	for key, e := range p.idle {
		switch {
		case key == k:
			delete(p.idle, key)
			if now.Sub(e.created) > p.maxAge() || now.Sub(e.used) > p.idleTTL() {
				drop = append(drop, e)
			} else {
				got = e
			}
		case key.ServerID == k.ServerID || endpoint(key.Address, key.Port) == endpoint(k.Address, k.Port):
			// Same server or endpoint, different identity: stale.
			delete(p.idle, key)
			drop = append(drop, e)
		}
	}
	p.mu.Unlock()
	closeAll(drop)
	if got == nil {
		return nil
	}
	got.timer.Stop()
	if !alive(got.s) {
		got.s.client.Close()
		return nil
	}
	got.s.created = got.created
	return got.s
}

// put keeps a connection that finished an operation without error.
func (p *Pool) put(k poolKey, s *session) {
	if p == nil {
		s.client.Close()
		return
	}
	now := p.now()
	created := s.created
	if created.IsZero() {
		created = now
	}
	if now.Sub(created) > p.maxAge() {
		s.client.Close()
		return
	}
	e := &pooled{s: s, key: k, created: created, used: now}
	p.mu.Lock()
	if p.idle == nil {
		p.idle = map[poolKey]*pooled{}
	}
	old := p.idle[k]
	p.idle[k] = e
	e.timer = time.AfterFunc(p.idleTTL(), func() { p.expire(k, e) })
	p.mu.Unlock()
	if old != nil {
		old.timer.Stop()
		old.s.client.Close()
	}
}

func (p *Pool) expire(k poolKey, e *pooled) {
	p.mu.Lock()
	if p.idle[k] == e {
		delete(p.idle, k)
	} else {
		e = nil
	}
	p.mu.Unlock()
	if e != nil {
		e.s.client.Close()
	}
}

func (p *Pool) drop(match func(poolKey) bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	var out []*pooled
	for k, e := range p.idle {
		if match(k) {
			out = append(out, e)
			delete(p.idle, k)
		}
	}
	p.mu.Unlock()
	closeAll(out)
}

// InvalidateServer closes every idle connection to the server.
func (p *Pool) InvalidateServer(id string) {
	p.drop(func(k poolKey) bool { return k.ServerID == id })
}

// InvalidateCredential closes every idle connection authenticated with the
// credential.
func (p *Pool) InvalidateCredential(id string) {
	p.drop(func(k poolKey) bool { return k.CredentialID == id })
}

// CloseAll closes every idle connection (cooldowns are kept).
func (p *Pool) CloseAll() { p.drop(func(poolKey) bool { return true }) }

// Idle is the number of idle connections (tests and diagnostics).
func (p *Pool) Idle() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

func closeAll(es []*pooled) {
	for _, e := range es {
		if e.timer != nil {
			e.timer.Stop()
		}
		e.s.client.Close()
	}
}

// alive sends an OpenSSH keepalive request; any answer (OpenSSH answers
// "failure" to unknown global requests) means the connection works.
func alive(s *session) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := s.client.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-ctx.Done():
		return false
	}
}

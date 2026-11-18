package sniff

// The forwarder's self-check of its real paths (docs/architecture.md
// 「转发服务自检」).
//
// The forwarder asks, from its own process — its uid, its socket marks,
// under its nft confinement (sniff_confine), through the routes, transit
// source translation and WireGuard tunnels its real connections use — every
// resolver of every target of its target file one fixed question, and for
// the default target (the default region group) opens one TCP connection to
// that target's resolver. Any well-formed DNS reply from the resolver, of
// any rcode (NXDOMAIN, REFUSED, SERVFAIL included), proves the round trip:
// the query left with the target's mark, was let out by the confinement,
// went through the tunnel (its outer WireGuard packet included) and the
// reply came back. A timeout, a send the kernel refused (EPERM: dropped in
// the output path), an unreachable route or an ICMP error does not.
//
// The question is ". IN NS" (the root zone's name servers): it names no site
// and nothing about the operator, every recursive resolver answers it (from
// its root priming, without asking anyone the operator could be told
// apart by), and neither a hub's group resolver nor an exit's resolver has a
// rule that would treat it specially. Nothing is sent to anyone but the
// target resolvers the forwarder already uses.
//
// The connection probe is a TCP handshake to the default target's first
// resolver on port 53, with that target's query mark, closed at once without
// a byte sent. For a region group the query mark is the group's connection
// mark, so the probe takes the path the forwarder's connections to that
// group take — mark, policy route, transit source translation, MSS clamp,
// the tunnel and its outer packets, the hub's return route — without naming
// any site or contacting a third party; the confinement already allows it
// (the target file's resolvers, TCP and UDP 53). What it does not exercise:
// relay sharing (sniff_route skips port 53) and any site beyond the tunnel.
//
// So the self-check proves, at the moment it ran, that each target's
// resolver was reachable from the forwarder and, for the default target,
// that a TCP connection through its tunnel opened. It does not prove that a
// given site works, that an exit reaches the internet, or that the answer
// was right.
//
// Bounds: one run at a time (requests queue behind it; a trigger while one
// is pending is merged); at most SelfCheckConcurrency probes in flight; each
// DNS probe SelfCheckQueryTimeout, the connection probe
// SelfCheckConnectTimeout, the whole run SelfCheckBudget (what has not run
// by then is reported "not_run"); a resolver the forwarder already knows as
// silent (Resolver health: demoted) is re-checked with the shorter
// SelfCheckRecheckTimeout, so one silent resolver does not make every
// periodic run wait the full query timeout; every probe is recorded in the
// resolver health the lookups use. At most SelfCheckMaxTargets targets and
// SelfCheckMaxResolvers resolvers each. It runs in its own goroutines and
// never holds anything forwarding needs.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Self-check constants.
const (
	SelfCheckVersion = 1
	// SelfCheckQName and SelfCheckQType are the fixed question.
	SelfCheckQName = "."
	SelfCheckQType = "NS"
	selfCheckQType = 2

	// SelfCheckQueryTimeout: some resolvers answer the root question only
	// after their own slow recursion (seen: SERVFAIL after 2–3 s while A
	// queries take 30–180 ms), so the wait is generous.
	SelfCheckQueryTimeout = 5 * time.Second
	// SelfCheckRecheckTimeout bounds the probe of a resolver the forwarder
	// already knows as silent (demoted: Resolver.HealthDemoteFor): the
	// periodic run re-checks it without waiting the full query timeout for
	// it every time. An answer within it ends the demotion at once.
	SelfCheckRecheckTimeout = 2 * time.Second
	SelfCheckConnectTimeout = 3 * time.Second
	// SelfCheckBudget: a DNS probe takes at most SelfCheckQueryTimeout
	// plus, after a timeout, SelfCheckConnectTimeout (the TCP follow-up);
	// with SelfCheckConcurrency workers a typical rule set (a few dozen
	// probes) finishes in two or three rounds.
	SelfCheckBudget       = 20 * time.Second
	SelfCheckConcurrency  = 16
	SelfCheckMaxTargets   = 64
	SelfCheckMaxResolvers = 4
	// SelfCheckMaxAge is how old a result may be to count as evidence for
	// an install (EvaluateSelfCheck).
	SelfCheckMaxAge = 2 * time.Minute
	// SelfCheckMarker is in every binary that has "meridian sniff-selfcheck"
	// (the generated verify script greps for it before running it).
	SelfCheckMarker = "meridian-sniff-selfcheck-v1"
	// DefaultSelfCheckInterval repeats the self-check while running (0:
	// only at start, after a reload and on request).
	DefaultSelfCheckInterval = 15 * time.Minute
)

// Triggers of a run.
const (
	TriggerStart    = "start"
	TriggerReload   = "reload"
	TriggerRequest  = "request"
	TriggerPeriodic = "periodic"
)

// Probe outcomes. Reached: answer, nxdomain, rcode (DNS) and connected (TCP).
const (
	OutcomeAnswer    = "answer"    // NOERROR
	OutcomeNXDomain  = "nxdomain"  // NXDOMAIN
	OutcomeRcode     = "rcode"     // another rcode (SERVFAIL, REFUSED…): the resolver answered
	OutcomeConnected = "connected" // TCP handshake completed
	OutcomeTimeout   = "timeout"   // nothing came back in time
	// OutcomeSlow: the UDP question timed out but a TCP connection to the
	// same resolver through the same mark opened: the path is proven, the
	// resolver is only slow with this question. Passes, with a warning.
	OutcomeSlow        = "slow"
	OutcomeSendRefused = "send_refused" // the kernel refused the send (EPERM/EACCES: dropped on the way out)
	OutcomeRefused     = "refused"      // ICMP port unreachable (UDP) or RST (TCP)
	OutcomeUnreachable = "unreachable"  // no route / host or network unreachable
	OutcomeMalformed   = "malformed"    // a reply that is not an answer to the question
	OutcomeError       = "error"        // anything else
	OutcomeNotRun      = "not_run"      // the run's budget ended first
)

// Target states.
const (
	TargetOK        = "ok"
	TargetFailed    = "failed"
	TargetUnchecked = "unchecked"
)

// SelfCheckProbe is one probe of one resolver.
type SelfCheckProbe struct {
	Server     string `json:"server"`
	Outcome    string `json:"outcome"`
	Rcode      int    `json:"rcode,omitempty"`
	Reached    bool   `json:"reached"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
	// TimeoutMS is how long this probe waited at most.
	TimeoutMS int64 `json:"timeout_ms,omitempty"`
	// KnownSilent: the resolver was demoted (it did not answer before), so
	// this probe used SelfCheckRecheckTimeout.
	KnownSilent bool `json:"known_silent,omitempty"`
	// Transport: how it was asked ("udp", TCP after a truncated reply).
	Transport string `json:"transport,omitempty"`
}

// SelfCheckTarget is one target's result.
type SelfCheckTarget struct {
	Target  string `json:"target"`
	Mark    uint32 `json:"mark"`
	DNSMark uint32 `json:"dns_mark"`
	Default bool   `json:"default,omitempty"`
	// Status: ok (a resolver answered and, where done, the connection
	// opened), failed, unchecked (no resolver, or over the limits).
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// Warning: the target passed only because a resolver was slow
	// (OutcomeSlow) and none answered in time.
	Warning   string           `json:"warning,omitempty"`
	Resolvers []SelfCheckProbe `json:"resolvers,omitempty"`
	Connect   *SelfCheckProbe  `json:"connect,omitempty"`
}

// SelfCheck is one run's result.
type SelfCheck struct {
	Version    int       `json:"version"`
	Trigger    string    `json:"trigger"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`
	// Generation is the forwarder's rule generation the run used;
	// TargetsSHA256 the SHA-256 of the target file it was loaded from (the
	// install's identity of that rule pair: the target file names its
	// snapshot's hash). Empty when the rules were not loaded from files.
	Generation    uint64 `json:"generation"`
	TargetsSHA256 string `json:"targets_sha256,omitempty"`
	QName         string `json:"qname"`
	QType         string `json:"qtype"`
	// Default is the default target's name ("" none).
	Default string `json:"default,omitempty"`
	// OK: the default target did not fail (ok, or unchecked because it has
	// no resolver).
	OK         bool              `json:"ok"`
	Incomplete bool              `json:"incomplete,omitempty"`
	Targets    []SelfCheckTarget `json:"targets"`
	// ResolverHealth is the forwarder's per-resolver record right after the
	// run (lookups and self-checks; Resolver.Health).
	ResolverHealth []ResolverHealth `json:"resolver_health,omitempty"`
}

// Failing lists the targets with status failed.
func (c *SelfCheck) Failing() []SelfCheckTarget {
	var out []SelfCheckTarget
	for _, t := range c.Targets {
		if t.Status == TargetFailed {
			out = append(out, t)
		}
	}
	return out
}

// DefaultResult is the default target's entry (nil when none).
func (c *SelfCheck) DefaultResult() *SelfCheckTarget {
	for i := range c.Targets {
		if c.Targets[i].Default {
			return &c.Targets[i]
		}
	}
	return nil
}

// ------------------------------------------------------------- running ---

type selfChecker struct {
	run     chan struct{} // one run at a time
	pending sync.Mutex    // guards queued
	queued  bool
	mu      sync.Mutex
	last    *SelfCheck
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	// The bounds (the Self-check constants; tests shorten them).
	queryTimeout, connectTimeout, budget, recheckTimeout time.Duration
	concurrency                                          int
}

func newSelfChecker() *selfChecker {
	ctx, cancel := context.WithCancel(context.Background())
	return &selfChecker{run: make(chan struct{}, 1), ctx: ctx, cancel: cancel,
		queryTimeout: SelfCheckQueryTimeout, connectTimeout: SelfCheckConnectTimeout, budget: SelfCheckBudget, concurrency: SelfCheckConcurrency,
		recheckTimeout: SelfCheckRecheckTimeout}
}

func (c *selfChecker) stop() {
	c.cancel()
	c.wg.Wait()
}

// LastSelfCheck is the most recent completed run (nil before the first).
func (s *Server) LastSelfCheck() *SelfCheck {
	s.sc.mu.Lock()
	defer s.sc.mu.Unlock()
	if s.sc.last == nil {
		return nil
	}
	c := *s.sc.last
	return &c
}

// RunSelfCheck runs the self-check now, after any run in progress, and
// returns its result. ctx bounds the wait for a run in progress; the run
// itself is bounded by SelfCheckBudget.
func (s *Server) RunSelfCheck(ctx context.Context, trigger string) (*SelfCheck, error) {
	select {
	case s.sc.run <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.sc.ctx.Done():
		return nil, errors.New("forwarder stopping")
	}
	defer func() { <-s.sc.run }()
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.sc.ctx, cancel)
	defer stop()
	res := s.selfCheck(rctx, trigger)
	s.sc.mu.Lock()
	s.sc.last = res
	s.sc.mu.Unlock()
	c := *res
	return &c, nil
}

// TriggerSelfCheck starts a run in the background (start, reload,
// periodic). A trigger while another one waits is merged with it; nothing
// here blocks the caller.
func (s *Server) TriggerSelfCheck(trigger string) {
	s.sc.pending.Lock()
	if s.sc.queued {
		s.sc.pending.Unlock()
		return
	}
	s.sc.queued = true
	s.sc.pending.Unlock()
	s.sc.wg.Add(1)
	go func() {
		defer s.sc.wg.Done()
		select {
		case s.sc.run <- struct{}{}:
		case <-s.sc.ctx.Done():
			s.sc.pending.Lock()
			s.sc.queued = false
			s.sc.pending.Unlock()
			return
		}
		s.sc.pending.Lock()
		s.sc.queued = false
		s.sc.pending.Unlock()
		res := s.selfCheck(s.sc.ctx, trigger)
		s.sc.mu.Lock()
		s.sc.last = res
		s.sc.mu.Unlock()
		<-s.sc.run
		if w := warnings(res); res.OK && w != "" {
			s.logf("meridian-sniff: self-check (%s, generation %d) passed with warnings: %s", trigger, res.Generation, w)
		}
		if !res.OK {
			s.logf("meridian-sniff: self-check (%s, generation %d) failed for the default target %s: %s", trigger, res.Generation, res.Default, defaultReason(res))
		}
	}()
}

// warnings joins the targets' warnings into one line.
func warnings(c *SelfCheck) string {
	var w []string
	for _, t := range c.Targets {
		if t.Warning != "" {
			w = append(w, t.Target+"："+t.Warning)
		}
	}
	return strings.Join(w, "；")
}

func defaultReason(c *SelfCheck) string {
	if d := c.DefaultResult(); d != nil {
		return d.Reason
	}
	return ""
}

type scJob struct {
	ti      int
	ri      int // resolver index; -1: the connection probe
	server  string
	t       Target
	connect bool
}

// selfCheck is one run against the rules installed now.
func (s *Server) selfCheck(ctx context.Context, trigger string) *SelfCheck {
	start := s.now()
	res := &SelfCheck{Version: SelfCheckVersion, Trigger: trigger, StartedAt: start, QName: SelfCheckQName, QType: SelfCheckQType}
	st := s.state.Load()
	if st == nil {
		res.FinishedAt = s.now()
		res.Incomplete = true
		return res
	}
	res.Generation, res.TargetsSHA256 = st.gen, st.sha
	def := st.c.DefaultTarget()
	var names []string
	for n, t := range st.targets {
		if !t.Reject {
			names = append(names, n)
		}
	}
	// The default target first, then by name: a stable order, and the one
	// that matters most is scheduled first.
	defName := ""
	if t, ok := st.byMark[def.Mark]; ok && def.Mark != 0 && !t.Reject {
		defName = t.Name
	}
	sort.Slice(names, func(i, j int) bool {
		if (names[i] == defName) != (names[j] == defName) {
			return names[i] == defName
		}
		return names[i] < names[j]
	})
	res.Default = defName
	var jobs []scJob
	for i, n := range names {
		t := st.targets[n]
		e := SelfCheckTarget{Target: t.Name, Mark: t.Mark, DNSMark: t.dnsMark(), Default: n == defName}
		switch {
		case i >= SelfCheckMaxTargets:
			e.Status, e.Reason = TargetUnchecked, "超出自检的目标数上限"
		case len(t.Resolvers) == 0:
			e.Status, e.Reason = TargetUnchecked, "这个目标没有解析器：按名字判断到它的连接会失败，自检无从检查"
		default:
			rs := t.Resolvers
			if len(rs) > SelfCheckMaxResolvers {
				rs = rs[:SelfCheckMaxResolvers]
			}
			for ri, r := range rs {
				e.Resolvers = append(e.Resolvers, SelfCheckProbe{Server: r, Outcome: OutcomeNotRun})
				jobs = append(jobs, scJob{ti: i, ri: ri, server: r, t: t})
			}
			if e.Default {
				e.Connect = &SelfCheckProbe{Server: rs[0], Outcome: OutcomeNotRun}
				jobs = append(jobs, scJob{ti: i, ri: -1, server: rs[0], t: t, connect: true})
			}
		}
		res.Targets = append(res.Targets, e)
	}
	bctx, cancel := context.WithTimeout(ctx, s.sc.budget)
	defer cancel()
	var mu sync.Mutex
	work := make(chan scJob)
	var wg sync.WaitGroup
	n := s.sc.concurrency
	if len(jobs) < n {
		n = len(jobs)
	}
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				var p SelfCheckProbe
				if j.connect {
					p = s.probeConnect(bctx, j.server, j.t.dnsMark())
				} else {
					p = s.probeDNS(bctx, j.server, j.t)
				}
				mu.Lock()
				if j.connect {
					res.Targets[j.ti].Connect = &p
				} else {
					res.Targets[j.ti].Resolvers[j.ri] = p
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, j := range jobs {
		select {
		case work <- j:
		case <-bctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	res.OK = true
	for i := range res.Targets {
		e := &res.Targets[i]
		if e.Status == TargetUnchecked {
			continue
		}
		e.Status, e.Reason, e.Warning = judgeTarget(e)
		for _, p := range e.Resolvers {
			res.Incomplete = res.Incomplete || p.Outcome == OutcomeNotRun
		}
		if e.Connect != nil && e.Connect.Outcome == OutcomeNotRun {
			res.Incomplete = true
		}
		if e.Default && e.Status == TargetFailed {
			res.OK = false
		}
	}
	res.ResolverHealth = s.Resolver.Health()
	res.FinishedAt = s.now()
	res.DurationMS = res.FinishedAt.Sub(start).Milliseconds()
	return res
}

// judgeTarget: ok when a resolver answered and the connection probe (if
// any) opened. A resolver that did not answer in time but whose TCP port
// opened through the same mark (OutcomeSlow) also proves the path: ok with
// a warning when no resolver answered. Anything else fails (fail closed).
func judgeTarget(e *SelfCheckTarget) (status, reason, warning string) {
	var reached bool
	var why, slow []string
	for _, p := range e.Resolvers {
		switch {
		case p.Reached:
			reached = true
		case p.Outcome == OutcomeSlow:
			slow = append(slow, "解析器 "+p.Server+" "+OutcomeText(p.Outcome))
		default:
			why = append(why, "解析器 "+p.Server+" "+OutcomeText(p.Outcome))
		}
	}
	if !reached && len(slow) == 0 {
		return TargetFailed, strings.Join(why, "；"), ""
	}
	if e.Connect != nil && !e.Connect.Reached {
		return TargetFailed, "解析器的路径可用，但到 " + e.Connect.Server + " 的 TCP 连接" + OutcomeText(e.Connect.Outcome), ""
	}
	if !reached {
		return TargetOK, "", strings.Join(slow, "；")
	}
	return TargetOK, "", ""
}

// OutcomeText is a probe outcome in plain words.
func OutcomeText(o string) string {
	switch o {
	case OutcomeAnswer:
		return "有回答"
	case OutcomeNXDomain:
		return "回答了 NXDOMAIN（路径可用）"
	case OutcomeRcode:
		return "回答了错误码（路径可用）"
	case OutcomeConnected:
		return "已建立"
	case OutcomeTimeout:
		return "超时，没有任何回应"
	case OutcomeSlow:
		return "没有按时回答，但 TCP 53 可以连通（路径可用，解析器慢）"
	case OutcomeSendRefused:
		return "发送被本机拒绝（在出站路径上被丢弃）"
	case OutcomeRefused:
		return "被对端拒绝（端口不可达或连接被重置）"
	case OutcomeUnreachable:
		return "不可达（没有路由）"
	case OutcomeMalformed:
		return "回答与问题不符"
	case OutcomeNotRun:
		return "没有来得及检查（自检总时限已到）"
	default:
		return "出错"
	}
}

// probeDNS asks server the fixed question for target t through the same
// exchange and mark as t's real resolutions (Resolver.exchange).
func (s *Server) probeDNS(ctx context.Context, server string, t Target) (p SelfCheckProbe) {
	p = SelfCheckProbe{Server: server, Outcome: OutcomeNotRun, Transport: "udp"}
	if ctx.Err() != nil {
		return p
	}
	timeout := s.sc.queryTimeout
	if s.Resolver.demoted(server, t.dnsMark()) && s.sc.recheckTimeout > 0 && s.sc.recheckTimeout < timeout {
		timeout, p.KnownSilent = s.sc.recheckTimeout, true
	}
	p.TimeoutMS = timeout.Milliseconds()
	start := time.Now()
	defer func() {
		d := time.Since(start)
		p.DurationMS = d.Milliseconds()
		// slow is neither an answer nor a silent path: not recorded.
		if p.Outcome != OutcomeNotRun && p.Outcome != OutcomeSlow {
			s.Resolver.observe(server, t.dnsMark(), p.Outcome, d, "selfcheck")
		}
	}()
	q, id, err := selfCheckQuery()
	if err != nil {
		p.Outcome, p.Error = OutcomeError, clipErr(err)
		return p
	}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := s.Resolver.exchange(qctx, t, server, q)
	if err != nil {
		p.Outcome, p.Error = classifyNetErr(qctx, err), clipErr(err)
		// A timeout alone does not tell a dead path from a slow resolver:
		// try a TCP connection to the same resolver through the same mark
		// (bounded by the run's budget). Only a completed handshake counts.
		if p.Outcome == OutcomeTimeout && ctx.Err() == nil {
			if c := s.probeConnect(ctx, server, t.dnsMark()); c.Reached {
				p.Outcome = OutcomeSlow
				p.Error = clipErr(fmt.Errorf("udp: %s; tcp connected in %d ms", p.Error, c.DurationMS))
			}
		}
		return p
	}
	rcode, err := parseSelfCheckReply(resp, id)
	if err != nil {
		p.Outcome, p.Error = OutcomeMalformed, clipErr(err)
		return p
	}
	p.Reached, p.Rcode = true, rcode
	switch rcode {
	case 0:
		p.Outcome = OutcomeAnswer
	case 3:
		p.Outcome = OutcomeNXDomain
	default:
		p.Outcome = OutcomeRcode
	}
	return p
}

func (s *Server) probeConnect(ctx context.Context, server string, mark uint32) (p SelfCheckProbe) {
	p = SelfCheckProbe{Server: server, Outcome: OutcomeNotRun}
	if ctx.Err() != nil {
		return p
	}
	start := time.Now()
	defer func() { p.DurationMS = time.Since(start).Milliseconds() }()
	dial := s.Dial
	if dial == nil {
		dial = DialMarked
	}
	cctx, cancel := context.WithTimeout(ctx, s.sc.connectTimeout)
	defer cancel()
	c, err := dial(cctx, "tcp", server, mark)
	if err != nil {
		p.Outcome, p.Error = classifyNetErr(cctx, err), clipErr(err)
		return p
	}
	c.Close()
	p.Outcome, p.Reached = OutcomeConnected, true
	return p
}

func classifyNetErr(ctx context.Context, err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || ctx.Err() != nil:
		return OutcomeTimeout
	case errors.As(err, &ne) && ne.Timeout():
		return OutcomeTimeout
	case errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES):
		return OutcomeSendRefused
	case errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET):
		return OutcomeRefused
	case errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH):
		return OutcomeUnreachable
	}
	return OutcomeError
}

func clipErr(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// selfCheckQuery is ". IN NS" with RD and an EDNS0 OPT record.
func selfCheckQuery() ([]byte, uint16, error) {
	var idb [2]byte
	if _, err := io.ReadFull(rand.Reader, idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	b := make([]byte, 12, 12+5+11)
	binary.BigEndian.PutUint16(b[0:], id)
	b[2] = 0x01                           // RD
	binary.BigEndian.PutUint16(b[4:], 1)  // QDCOUNT
	binary.BigEndian.PutUint16(b[10:], 1) // ARCOUNT (OPT)
	b = append(b, 0, 0, selfCheckQType, 0, 1)
	b = append(b, 0, 0, byte(typeOPT), 0x04, 0xd0, 0, 0, 0, 0, 0, 0)
	return b, id, nil
}

// parseSelfCheckReply: a response (QR) to our id with our question (root,
// NS, IN); returns its rcode. Answer records are not read. An error reply
// (rcode != 0) with an empty question section is accepted too: SmartDNS
// answers a failed upstream lookup with a bare 12-byte header
// (QDCOUNT 0, SERVFAIL), which still proves the resolver answered.
func parseSelfCheckReply(b []byte, id uint16) (int, error) {
	if len(b) < 12 || binary.BigEndian.Uint16(b) != id || b[2]&0x80 == 0 {
		return 0, errors.New("reply does not match the query")
	}
	if rcode := int(b[3] & 0x0f); rcode != 0 && binary.BigEndian.Uint16(b[4:]) == 0 {
		return rcode, nil
	}
	if len(b) < 17 {
		return 0, errors.New("reply does not match the query")
	}
	if binary.BigEndian.Uint16(b[4:]) != 1 || b[12] != 0 || binary.BigEndian.Uint16(b[13:]) != selfCheckQType || binary.BigEndian.Uint16(b[15:]) != 1 {
		return 0, errors.New("reply question does not match")
	}
	return int(b[3] & 0x0f), nil
}

// ----------------------------------------------------------- evaluation ---

// Verdict codes of EvaluateSelfCheck.
const (
	VerdictOK              = "ok"
	VerdictDefaultFailed   = "default_failed"
	VerdictUnavailable     = "unavailable"      // no result: no forwarder, no target file, no report
	VerdictTimeout         = "timeout"          // no result in time: the rules were not loaded, or the run was not answered
	VerdictStaleGeneration = "stale_generation" // a result for other rules
	VerdictStale           = "stale"            // too old, or from before it was asked for
)

// Verdict is what an install, the panel and the verify script make of one
// self-check result.
type Verdict struct {
	Code string `json:"code"`
	// OK: the install may stand (the default target passed).
	OK      bool   `json:"ok"`
	Reason  string `json:"reason,omitempty"`
	Default string `json:"default,omitempty"`
	// Failing are the other targets that failed (warnings), "target: reason".
	Failing []string `json:"failing,omitempty"`
	// Notes are facts worth showing (an unchecked default target).
	Notes []string `json:"notes,omitempty"`
}

// EvaluateSelfCheck judges c as evidence for the rule pair whose target
// file hashes to wantSHA (hex SHA-256): the result must be for exactly that
// file, must have started no earlier than notBefore (zero: no bound) and
// finished at most SelfCheckMaxAge before now. A missing, stale or other
// generation's result fails (fail closed), as does a failed default target;
// other targets that failed are warnings.
func EvaluateSelfCheck(c *SelfCheck, wantSHA string, notBefore, now time.Time) Verdict {
	switch {
	case c == nil:
		return Verdict{Code: VerdictUnavailable, Reason: "没有自检结果"}
	case c.Version != SelfCheckVersion:
		return Verdict{Code: VerdictUnavailable, Reason: fmt.Sprintf("自检结果的格式版本 %d 不认识", c.Version)}
	case wantSHA == "" || !strings.EqualFold(c.TargetsSHA256, wantSHA):
		return Verdict{Code: VerdictStaleGeneration, Reason: fmt.Sprintf("自检结果属于另一版规则（目标文件 %.12s…，本次安装的是 %.12s…），不能作为本次安装的证据", c.TargetsSHA256, wantSHA)}
	case !notBefore.IsZero() && c.StartedAt.Before(notBefore.Add(-time.Second)):
		return Verdict{Code: VerdictStale, Reason: "自检结果早于本次请求，不能作为本次安装的证据"}
	case now.Sub(c.FinishedAt) > SelfCheckMaxAge:
		return Verdict{Code: VerdictStale, Reason: fmt.Sprintf("自检结果已过时（%s 前）", now.Sub(c.FinishedAt).Round(time.Second))}
	}
	v := Verdict{Code: VerdictOK, OK: true, Default: c.Default}
	for _, t := range c.Targets {
		switch {
		case t.Default && t.Status == TargetFailed:
			v.Code, v.OK = VerdictDefaultFailed, false
			v.Reason = "默认目标 " + t.Target + " 的路径不通：" + t.Reason
		case t.Default && t.Status == TargetUnchecked:
			v.Notes = append(v.Notes, "默认目标 "+t.Target+" 没有自检："+t.Reason)
		case t.Warning != "":
			v.Notes = append(v.Notes, "目标 "+t.Target+" 通过但有警告："+t.Warning)
		case t.Status == TargetFailed:
			v.Failing = append(v.Failing, t.Target+"："+t.Reason)
		}
	}
	if c.Default == "" {
		v.Notes = append(v.Notes, "规则没有可自检的默认目标")
	}
	return v
}

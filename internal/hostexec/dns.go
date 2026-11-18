package hostexec

// The read-only exit resolver check (POST /v1/dns/check;
// docs/architecture.md「解析配置视图」).
//
// The gateway asks one exit's tunnel resolver — the address the gateway's
// own SmartDNS forwards that exit's names to — one fixed question,
// DNSCheckName A, exactly the way that SmartDNS does: plain DNS from this
// host with no mark, through the WireGuard tunnel to the exit, whose
// SmartDNS answers from its cache or asks its configured upstream from the
// exit's own uplink. The caller names the exit and that resolver address
// only; the agent accepts the address only when the installed gateway
// SmartDNS config forwards to it (a "server <addr> -group …" line), so it
// cannot be pointed anywhere else. No name, server, port, type, mark or
// command is a parameter. Bounded by DNSCheckTimeout; shares the probes'
// interlock (no check while an install or rollback runs) and their limit.
//
// What it proves: the exit's resolver answered through the tunnel and,
// unless the answer came from its cache, its configured upstream answered
// it (with an upstream configured there is no other upstream on the exit).
// It cannot tell which upstream answered, nor whether an answer was
// cached; it never contacts the upstream directly.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

// DNSCheckName is the fixed question: a name reserved for documentation
// (RFC 2606, IANA-operated), which names nothing about the operator.
const DNSCheckName = "example.com"

// DNSCheckTimeout bounds the whole check.
const DNSCheckTimeout = 4 * time.Second

// DNSCheckRequest is the whole parameter set of the check.
type DNSCheckRequest struct {
	RequestID string `json:"request_id"`
	ExitID    string `json:"exit_id"`
	// Resolver is the exit's tunnel resolver address (fd66::/48).
	Resolver string `json:"resolver"`
}

// DNSCheckResult is the answer.
type DNSCheckResult struct {
	ExitID   string `json:"exit_id"`
	Resolver string `json:"resolver"`
	Name     string `json:"name"`
	QType    string `json:"qtype"`
	// Outcome: answer (NOERROR), nxdomain, rcode (another rcode, e.g.
	// SERVFAIL: the exit's resolver got no usable upstream answer),
	// timeout, refused, unreachable, malformed, error, not_allowed.
	Outcome    string    `json:"outcome"`
	Rcode      int       `json:"rcode,omitempty"`
	Answers    int       `json:"answers"`
	DurationMS int64     `json:"duration_ms"`
	CheckedAt  time.Time `json:"checked_at"`
	Error      string    `json:"error,omitempty"`
}

// ValidateDNSCheck checks a request completely before anything runs.
func ValidateDNSCheck(req DNSCheckRequest) error {
	if !requestIDRe.MatchString(req.RequestID) {
		return errors.New("request_id 不合法")
	}
	if !exitIDRe.MatchString(req.ExitID) {
		return errors.New("exit_id 不合法")
	}
	res, err := netip.ParseAddr(req.Resolver)
	if err != nil || !res.Is6() || res.Zone() != "" || !tunnelULA.Contains(res) || transit6.Contains(res) {
		return errors.New("resolver 必须是 fd66::/48 里的出口隧道解析地址")
	}
	return nil
}

// gatewayForwardsTo reports whether the installed gateway SmartDNS config
// has a "server <addr> …" line for addr (the exits' tunnel resolvers).
func gatewayForwardsTo(conf string, addr netip.Addr) (bool, error) {
	f, err := os.Open(conf)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 32<<20))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 3 || fs[0] != "server" || fs[2] != "-group" {
			continue
		}
		if a, err := netip.ParseAddr(strings.Trim(fs[1], "[]")); err == nil && a == addr {
			return true, nil
		}
	}
	return false, sc.Err()
}

// randReader is the source of query ids.
var randReader = rand.Reader

func dnsCheckQuery() ([]byte, uint16, error) { return dnsQuery(DNSCheckName) }

// parseDNSCheckReply: our id and question; returns rcode and answer count.
func parseDNSCheckReply(b, q []byte, id uint16) (int, int, error) {
	if len(b) < len(q) || binary.BigEndian.Uint16(b) != id || b[2]&0x80 == 0 || binary.BigEndian.Uint16(b[4:]) != 1 {
		return 0, 0, errors.New("reply does not match the query")
	}
	if string(b[12:len(q)]) != string(q[12:]) {
		return 0, 0, errors.New("reply question does not match")
	}
	return int(b[3] & 0x0f), int(binary.BigEndian.Uint16(b[6:])), nil
}

// DNSCheck validates and runs one check. The HTTP status is 200 for a
// check that ran (whatever its outcome), 4xx for a refused request and 503
// when busy.
func (a *Agent) DNSCheck(ctx context.Context, req DNSCheckRequest) (DNSCheckResult, int) {
	a.init()
	res := DNSCheckResult{ExitID: req.ExitID, Resolver: req.Resolver, Name: DNSCheckName, QType: "A", CheckedAt: time.Now().UTC()}
	if err := ValidateDNSCheck(req); err != nil {
		res.Outcome, res.Error = "not_allowed", err.Error()
		return res, http.StatusBadRequest
	}
	addr, _ := netip.ParseAddr(req.Resolver)
	conf := a.SmartDNSConf
	if conf == "" {
		conf = "/etc/smartdns/smartdns.conf"
	}
	ok, err := gatewayForwardsTo(conf, addr)
	if err != nil || !ok {
		res.Outcome = "not_allowed"
		res.Error = "网关上已安装的 SmartDNS 配置里没有转发到 " + addr.String() + " 的出口解析器：没有发出查询（先安装网关）"
		if err != nil {
			res.Error = "读不到网关上已安装的 SmartDNS 配置：没有发出查询"
		}
		return res, http.StatusOK
	}
	pctx, done, err := a.beginProbe(ctx)
	if err != nil {
		res.Outcome, res.Error = "error", err.Error()
		return res, http.StatusServiceUnavailable
	}
	defer done()
	cctx, cancel := context.WithTimeout(pctx, DNSCheckTimeout)
	defer cancel()
	q, id, err := dnsCheckQuery()
	if err != nil {
		res.Outcome, res.Error = "error", err.Error()
		return res, http.StatusOK
	}
	ex := a.DNSCheckExchange
	if ex == nil {
		ex = sniff.ExchangeNet
	}
	start := time.Now()
	resp, err := ex(cctx, netip.AddrPortFrom(addr, 53).String(), 0, q)
	res.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Outcome, res.Error = classifyDNSCheckErr(cctx, err), clipShort(err.Error())
		return res, http.StatusOK
	}
	rc, n, err := parseDNSCheckReply(resp, q, id)
	switch {
	case err != nil:
		res.Outcome, res.Error = "malformed", err.Error()
	case rc == 0:
		res.Outcome, res.Answers = "answer", n
	case rc == 3:
		res.Outcome = "nxdomain"
	default:
		res.Outcome, res.Rcode = "rcode", rc
	}
	return res, http.StatusOK
}

func classifyDNSCheckErr(ctx context.Context, err error) string {
	var ne net.Error
	switch {
	case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case strings.Contains(err.Error(), "connection refused"):
		return "refused"
	case strings.Contains(err.Error(), "unreachable"):
		return "unreachable"
	}
	return "error"
}

func clipShort(s string) string {
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

func (a *Agent) serveDNSCheck(w http.ResponseWriter, r *http.Request) {
	if !a.authorize(w, r) {
		return
	}
	var req DNSCheckRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, DNSCheckResult{Outcome: "not_allowed", Error: "请求格式不正确"})
		return
	}
	res, code := a.DNSCheck(r.Context(), req)
	writeJSON(w, code, res)
}

// DNSCheck sends one check request (not retried).
func (c *Client) DNSCheck(ctx context.Context, req DNSCheckRequest) (DNSCheckResult, error) {
	if err := ValidateDNSCheck(req); err != nil {
		return DNSCheckResult{}, err
	}
	var res DNSCheckResult
	code, err := c.post(ctx, "/v1/dns/check", req, DNSCheckTimeout+20*time.Second, &res)
	if err != nil {
		return res, err
	}
	switch code {
	case http.StatusOK:
		return res, nil
	case http.StatusServiceUnavailable:
		return res, fmt.Errorf("%w（%s）", ErrProbeBusy, res.Error)
	default:
		return res, fmt.Errorf("host agent 拒绝解析检查（%d）：%s", code, res.Error)
	}
}

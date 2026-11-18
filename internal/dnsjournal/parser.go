package dnsjournal

// The audit line of the gateway's SmartDNS, as observed on 2026-11-15 with
// SmartDNS 1.2026.11.09-1240 (the version a real gateway's resolver
// container ran; docs/architecture.md「网关解析日志」has every observation,
// where it was made and what was not observed). One line per answered
// query:
//
//	[2026-11-15 12:09:35,961] 192.0.2.10 query a.example.test, type 1, time 0ms, speed: -0.1ms, group default, result 192.0.2.1
//
// Fields: a local timestamp with milliseconds and no zone, the client
// address (an IPv6 client as its address, an IPv4 client of a dual-stack
// listener as plain IPv4), the name as asked (lower-cased by the resolver,
// otherwise unescaped: blanks and commas in a name are written as they
// are), the numeric query type, the total time in milliseconds, a "speed"
// value this journal does not keep, the upstream group that handled the
// query ("default" or a "-group" name) and the answer addresses separated
// by ", " (empty when there was none). The line carries no rcode.
//
// The parser is anchored on the right: the name is everything between
// "query " and the LAST ", type N, time Nms, speed: Xms, group G, result R"
// tail of the line, so a name that itself contains such text cannot set the
// type, time, group or result of its own line. It stays tolerant where
// another version might differ: answers are split on commas and blanks
// (tokens that are not addresses are counted apart), an IPv4-mapped or
// bracketed client address is accepted and unmapped, control characters are
// removed from a name and it is cut to MaxName bytes. A line that does not
// match is counted by the reader and never printed or logged.

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits of one raw audit line and of the fields kept from it.
const (
	// MaxRawLine bounds one audit line (a longer line is counted as bad:
	// the observed lines are about 130 bytes).
	MaxRawLine = 2048
	// MaxName bounds the name kept (a DNS name is at most 253 bytes).
	MaxName = 253
	// MaxGroup bounds the group name kept.
	MaxGroup = 64
	// MaxAnswerTokens bounds the tokens counted in a result.
	MaxAnswerTokens = 64
)

// Raw is one parsed audit line, before the reader adds what the line does
// not carry (the zone of its timestamp, the client's MAC).
type Raw struct {
	// Naive is the line's timestamp read as if it were UTC (the line has no
	// zone; Tailer establishes the offset).
	Naive   time.Time
	Client  netip.Addr
	Name    string
	QType   int
	Elapsed int64 // milliseconds
	Group   string
	// Answers counts the addresses in the result; Other the result tokens
	// that are not addresses.
	Answers, Other int
}

// ErrNoMatch is every parse failure: the reader counts it and says nothing
// about the line.
var ErrNoMatch = errors.New("not an audit line")

var auditLineRe = regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[,.](\d{3})\] (\S{1,80}) query (.*), type (\d{1,5}), time (\d{1,12})ms, speed: -?[0-9.]{1,16}ms, group (\S{0,128}), result ?(.*)$`)

// ParseLine parses one audit line (without its newline).
func ParseLine(line []byte) (Raw, error) {
	var r Raw
	if len(line) == 0 || len(line) > MaxRawLine || !utf8.Valid(line) {
		return r, ErrNoMatch
	}
	m := auditLineRe.FindSubmatch(line)
	if m == nil {
		return r, ErrNoMatch
	}
	ts, err := time.Parse("2006-01-02 15:04:05", string(m[1]))
	if err != nil {
		return r, ErrNoMatch
	}
	ms, _ := strconv.Atoi(string(m[2]))
	r.Naive = ts.Add(time.Duration(ms) * time.Millisecond)
	c, ok := parseClient(string(m[3]))
	if !ok {
		return r, ErrNoMatch
	}
	r.Client = c
	r.Name = normName(string(m[4]))
	if r.Name == "" {
		return r, ErrNoMatch
	}
	qt, err := strconv.Atoi(string(m[5]))
	if err != nil || qt < 0 || qt > 65535 {
		return r, ErrNoMatch
	}
	r.QType = qt
	el, err := strconv.ParseInt(string(m[6]), 10, 64)
	if err != nil {
		return r, ErrNoMatch
	}
	r.Elapsed = el
	r.Group = clip(string(m[7]), MaxGroup)
	n := 0
	for _, tok := range strings.FieldsFunc(string(m[8]), func(c rune) bool { return c == ',' || c == ' ' || c == '\t' || c == ';' }) {
		if n++; n > MaxAnswerTokens {
			break
		}
		if _, err := netip.ParseAddr(tok); err == nil {
			r.Answers++
		} else {
			r.Other++
		}
	}
	return r, nil
}

// parseClient accepts an address, a bracketed address and an address with a
// port; the result is unmapped and has no zone.
func parseClient(s string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a.Unmap().WithZone(""), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

// normName lower-cases a name, drops control characters and a trailing dot
// and cuts it to MaxName bytes.
func normName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s != "." {
		s = strings.TrimSuffix(s, ".")
	}
	return clip(s, MaxName)
}

// clip cuts s to at most n bytes on a rune boundary and drops control
// characters.
func clip(s string, n int) string {
	if strings.ContainsFunc(s, isCtl) {
		s = strings.Map(func(r rune) rune {
			if isCtl(r) {
				return -1
			}
			return r
		}, s)
	}
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func isCtl(r rune) bool { return r < 0x20 || r == 0x7f }

// Result classes of a record. The audit line has no rcode, so the class
// comes from two things only: whether the result is empty and how long the
// query took.
//
//   - ResultAnswered: the result holds at least one token (addresses).
//   - ResultNoAnswer: the result is empty and the query took less than
//     SlowEmptyMS. Observed for a name that does not exist (NXDOMAIN, 3 ms).
//     A name that exists without a record of the asked type (NODATA) and an
//     upstream that refused quickly look the same and cannot be told apart.
//   - ResultNoAnswerSlow: the result is empty and the query took
//     SlowEmptyMS or longer. Observed for an upstream that did not answer
//     (about 2 s). A slow NXDOMAIN looks the same: "probably failed or
//     timed out", never "failed".
//
// Never in the journal: a name a rule of the resolver answers itself (an
// "address /name/#" block, answered NXDOMAIN to the client) produced no
// audit line at all on the observed binary. "Blocked by a rule" is
// therefore not a class: such queries are absent, not misfiled.
const (
	ResultAnswered     = "answered"
	ResultNoAnswer     = "no_answer"
	ResultNoAnswerSlow = "no_answer_slow"
	// ResultNoAnswerAny is a filter only: both empty classes.
	ResultNoAnswerAny = "no_answer_any"
	// SlowEmptyMS separates the two empty classes.
	SlowEmptyMS = 1500
)

// Classify is the result class of a parsed line.
func Classify(answers, other int, elapsedMS int64) string {
	switch {
	case answers+other > 0:
		return ResultAnswered
	case elapsedMS >= SlowEmptyMS:
		return ResultNoAnswerSlow
	}
	return ResultNoAnswer
}

// QTypeNames are the query types the panel names (others show as numbers).
var QTypeNames = map[int]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}

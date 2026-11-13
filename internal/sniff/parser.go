package sniff

// The parsers below are written from the public specifications only:
//
//   - TLS record layer and ClientHello: RFC 8446 §5.1 (records, handshake
//     fragmentation and the ban on interleaving), §4.1.2 (ClientHello),
//     §4.2 (extensions, no duplicates); RFC 5246 §7.4.1.2 for the TLS 1.2
//     form without extensions.
//   - server_name: RFC 6066 §3 (one host_name, no trailing dot, no IP
//     literal).
//   - encrypted_client_hello: draft-ietf-tls-esni (code point 0xfe0d); the
//     older encrypted_server_name code point 0xffce is recognized too.
//   - HTTP/1.1 request line, header fields and Host: RFC 9112 §3, §5,
//     §3.2.2 and RFC 9110 §7.2, §5.6.2 (tchar).
//
// No code was taken from another implementation.

import (
	"bytes"
	"net/netip"
	"strings"

	"github.com/radowitz/meridian/internal/ordered"
)

// Proto is what the first bytes of a connection were recognized as.
type Proto string

const (
	// ProtoNone: nothing recognized (another protocol, or no data).
	ProtoNone Proto = ""
	// ProtoTLS: a TLS ClientHello.
	ProtoTLS Proto = "tls"
	// ProtoHTTP: an HTTP/1.x request.
	ProtoHTTP Proto = "http"
)

// Why a sniff produced no name. Stable strings: the recent-connection
// record and the counters use them.
const (
	WhyNone       = ""             // a name was found
	WhyNoSNI      = "no_sni"       // ClientHello without server_name
	WhyBadSNI     = "bad_sni"      // server_name is not a host name (IP literal, bad characters)
	WhyECH        = "ech"          // encrypted_client_hello present (see Result.ECH)
	WhyMalformed  = "malformed"    // TLS or HTTP framing broken
	WhyOversized  = "oversized"    // the ClientHello or header block exceeds the read limit
	WhyOther      = "other"        // neither TLS nor HTTP/1
	WhyHTTP2      = "http2"        // HTTP/2 prior-knowledge preface (no Host to read)
	WhyNoHost     = "no_host"      // HTTP request without a usable Host
	WhyIPHost     = "ip_host"      // HTTP Host is an address literal
	WhyTimeout    = "timeout"      // the client sent too little before the sniff deadline
	WhyNoData     = "no_data"      // the client sent nothing before the sniff deadline
	WhyEOF        = "eof"          // the client closed before a decision
	WhySkipped    = "skipped_port" // the destination port is not sniffed
	WhyReadFailed = "read_failed"  // other read error
	// Server-side refinements of WhyECH in the recent record (not parser
	// results): the cleartext name decided (Config.ECHOuter), or it is one
	// of Config.ECHPublicNames and the address decided.
	WhyECHOuter  = "ech_outer"
	WhyECHPublic = "ech_public"
)

// Result of a sniff.
type Result struct {
	Proto Proto
	// Name is the normalized host name (ordered.NormDomain), "" when there
	// is none; Why then says why.
	Name string
	Why  string
	// ECH: the ClientHello carries encrypted_client_hello. Name is then
	// empty and OuterName holds the cleartext server_name, which is the
	// ECH provider's public name when ECH is real and the true name when the
	// client only sends a GREASE ECH extension; the two cannot be told apart
	// on the wire (that is the point of ECH). The server decides what to do
	// with it (Config.ECHOuter).
	ECH       bool
	OuterName string
}

// Sniff inspects the first bytes of a connection (everything received so
// far). more reports that the bytes are a proper prefix of a TLS
// ClientHello or HTTP/1 request head and more data is needed; max is the
// most bytes the caller will ever buffer, so a message that cannot fit is
// reported as WhyOversized at once.
func Sniff(b []byte, max int) (r Result, more bool) {
	if len(b) == 0 {
		return Result{Why: WhyNoData}, true
	}
	if b[0] == recordHandshake {
		return sniffTLS(b, max)
	}
	return sniffHTTP(b, max)
}

// ------------------------------------------------------------------ TLS ---

const (
	recordHandshake      = 22
	handshakeClientHello = 1
	maxRecordPlaintext   = 1 << 14 // RFC 8446 §5.1
	extServerName        = 0
	extECH               = 0xfe0d
	extESNI              = 0xffce
)

func sniffTLS(b []byte, max int) (Result, bool) {
	tls := Result{Proto: ProtoTLS}
	var hs []byte // handshake bytes reassembled from consecutive records
	off := 0
	for {
		if len(hs) >= 4 {
			if hs[0] != handshakeClientHello {
				tls.Why = WhyMalformed
				return tls, false
			}
			n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			// The message, its header and at least one record header per
			// 2^14 bytes must fit in max.
			if 4+n+5*(1+(4+n)/maxRecordPlaintext) > max {
				tls.Why = WhyOversized
				return tls, false
			}
			if len(hs) >= 4+n {
				return parseClientHello(hs[4:4+n], tls), false
			}
		}
		if off+5 > len(b) {
			if off+5 > max {
				tls.Why = WhyOversized
				return tls, false
			}
			return tls, true
		}
		// Every record until the ClientHello is complete is a handshake
		// record (RFC 8446 §5.1: handshake messages are not interleaved
		// with other record types), version 3.x, non-empty, at most 2^14.
		typ, major, minor := b[off], b[off+1], b[off+2]
		l := int(b[off+3])<<8 | int(b[off+4])
		if typ != recordHandshake || major != 3 || minor > 4 || l == 0 || l > maxRecordPlaintext {
			if off == 0 && (major != 3 || minor > 4) {
				// 0x16 followed by something that is not a TLS version:
				// not TLS at all rather than broken TLS.
				tls = Result{Why: WhyOther}
				return tls, false
			}
			tls.Why = WhyMalformed
			return tls, false
		}
		if off+5+l > len(b) {
			if off+5+l > max {
				tls.Why = WhyOversized
				return tls, false
			}
			return tls, true
		}
		hs = append(hs, b[off+5:off+5+l]...)
		off += 5 + l
	}
}

// reader is a bounds-checked cursor; any short read sets bad.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) n(k int) []byte {
	if r.bad || k < 0 || k > len(r.b) {
		r.bad = true
		return nil
	}
	out := r.b[:k]
	r.b = r.b[k:]
	return out
}

func (r *reader) u8() int {
	x := r.n(1)
	if x == nil {
		return 0
	}
	return int(x[0])
}

func (r *reader) u16() int {
	x := r.n(2)
	if x == nil {
		return 0
	}
	return int(x[0])<<8 | int(x[1])
}

// vec reads a vector with a 1- or 2-byte length prefix.
func (r *reader) vec(prefix int) []byte {
	var l int
	if prefix == 1 {
		l = r.u8()
	} else {
		l = r.u16()
	}
	return r.n(l)
}

// parseClientHello reads the ClientHello body (RFC 8446 §4.1.2).
func parseClientHello(body []byte, res Result) Result {
	r := &reader{b: body}
	r.n(2)  // legacy_version
	r.n(32) // random
	if sid := r.vec(1); len(sid) > 32 {
		r.bad = true
	}
	if cs := r.vec(2); len(cs) < 2 || len(cs)%2 != 0 {
		r.bad = true
	}
	if cm := r.vec(1); len(cm) < 1 {
		r.bad = true
	}
	if r.bad {
		res.Why = WhyMalformed
		return res
	}
	if len(r.b) == 0 {
		// TLS 1.2 and earlier may omit the extensions block.
		res.Why = WhyNoSNI
		return res
	}
	exts := r.vec(2)
	if r.bad || len(r.b) != 0 {
		res.Why = WhyMalformed
		return res
	}
	er := &reader{b: exts}
	seen := map[int]bool{}
	var sni string
	sniSeen, sniBad := false, false
	for len(er.b) > 0 {
		typ := er.u16()
		data := er.vec(2)
		if er.bad || seen[typ] {
			res.Why = WhyMalformed
			return res
		}
		seen[typ] = true
		switch typ {
		case extServerName:
			name, ok, malformed := parseServerName(data)
			if malformed {
				res.Why = WhyMalformed
				return res
			}
			sniSeen = true
			if ok {
				sni = name
			} else {
				sniBad = true
			}
		case extECH, extESNI:
			res.ECH = true
		}
	}
	switch {
	case res.ECH:
		res.OuterName = sni
		res.Why = WhyECH
	case sni != "":
		res.Name = sni
	case sniSeen && sniBad:
		res.Why = WhyBadSNI
	default:
		res.Why = WhyNoSNI
	}
	return res
}

// parseServerName reads ServerNameList (RFC 6066 §3). ok false when the
// extension is well formed but holds no usable host name (IP literal,
// characters a DNS name cannot have, no host_name entry).
func parseServerName(data []byte) (name string, ok, malformed bool) {
	r := &reader{b: data}
	list := r.vec(2)
	if r.bad || len(r.b) != 0 || len(list) == 0 {
		return "", false, true
	}
	lr := &reader{b: list}
	host := ""
	hostSeen := false
	for len(lr.b) > 0 {
		typ := lr.u8()
		v := lr.vec(2)
		if lr.bad || len(v) == 0 {
			return "", false, true
		}
		if typ != 0 {
			continue // unknown name types are skipped
		}
		if hostSeen {
			return "", false, true // RFC 6066: one name per type
		}
		hostSeen = true
		host = string(v)
	}
	if !hostSeen {
		return "", false, false
	}
	return normHost(host)
}

// normHost: a DNS host name, not an address literal; a trailing dot is
// not allowed in SNI (RFC 6066) and is tolerated in Host (RFC 9110 allows
// the absolute form), normalized away by ordered.NormDomain.
func normHost(h string) (string, bool, bool) {
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return "", false, false
	}
	n, ok := ordered.NormDomain(h)
	if !ok {
		return "", false, false
	}
	// A name of digits and dots only is an address-like string, not a
	// name (e.g. "1.2.3", "010.1.1.1").
	if strings.Trim(n, "0123456789.") == "" {
		return "", false, false
	}
	return n, true, false
}

// ----------------------------------------------------------------- HTTP ---

const maxMethod = 20

func isTchar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// line returns the line at the start of b (without CRLF or bare LF, RFC
// 9112 §2.2 allows a recipient to accept a bare LF) and its length with
// the terminator; ok false when no terminator is in b yet.
func line(b []byte) (l []byte, n int, ok bool) {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return nil, 0, false
	}
	l = b[:i]
	if len(l) > 0 && l[len(l)-1] == '\r' {
		l = l[:len(l)-1]
	}
	return l, i + 1, true
}

func sniffHTTP(b []byte, max int) (Result, bool) {
	other := Result{Why: WhyOther}
	// Method: a token followed by SP. Everything else is another protocol.
	i := 0
	for i < len(b) && i <= maxMethod && isTchar(b[i]) {
		i++
	}
	switch {
	case i == len(b) && i <= maxMethod:
		return other, true // still a possible method
	case i == 0 || i > maxMethod || b[i] != ' ':
		return other, false
	}
	req, n, ok := line(b)
	if !ok {
		if len(b) >= max {
			return Result{Proto: ProtoHTTP, Why: WhyOversized}, false
		}
		// The request line is not complete. Bytes that cannot be in a
		// request line end the guess early.
		if bytes.ContainsAny(b, "\x00") {
			return other, false
		}
		return other, true
	}
	parts := strings.Split(string(req), " ")
	if len(parts) != 3 || parts[1] == "" || !strings.HasPrefix(parts[2], "HTTP/") {
		return other, false
	}
	ver := parts[2]
	if ver == "HTTP/2.0" {
		return Result{Why: WhyHTTP2}, false
	}
	if len(ver) != 8 || ver[5] != '1' || ver[6] != '.' || ver[7] < '0' || ver[7] > '9' {
		return other, false
	}
	res := Result{Proto: ProtoHTTP}
	target := parts[1]
	method := parts[0]
	// Header fields up to the empty line.
	rest := b[n:]
	var hosts []string
	for {
		l, k, ok := line(rest)
		if !ok {
			if len(b) >= max {
				res.Why = WhyOversized
				return res, false
			}
			return res, true
		}
		rest = rest[k:]
		if len(l) == 0 {
			break
		}
		if l[0] == ' ' || l[0] == '\t' {
			res.Why = WhyMalformed // obs-fold (RFC 9112 §5.2)
			return res, false
		}
		c := bytes.IndexByte(l, ':')
		if c <= 0 {
			res.Why = WhyMalformed
			return res, false
		}
		for _, x := range l[:c] {
			if !isTchar(x) { // includes whitespace before the colon (§5.1)
				res.Why = WhyMalformed
				return res, false
			}
		}
		if strings.EqualFold(string(l[:c]), "host") {
			hosts = append(hosts, strings.Trim(string(l[c+1:]), " \t"))
		}
	}
	if len(hosts) > 1 {
		res.Why = WhyMalformed // RFC 9112 §3.2: more than one Host
		return res, false
	}
	// absolute-form (RFC 9112 §3.2.2) or authority-form (CONNECT): the
	// request-target's authority wins over Host.
	auth := ""
	switch {
	case method == "CONNECT":
		auth = target
	case hasSchemePrefix(target, "http://"):
		auth = target[len("http://"):]
	case hasSchemePrefix(target, "https://"):
		auth = target[len("https://"):]
	}
	if auth != "" {
		if j := strings.IndexAny(auth, "/?#"); j >= 0 {
			auth = auth[:j]
		}
		if j := strings.LastIndexByte(auth, '@'); j >= 0 {
			auth = auth[j+1:]
		}
	} else if len(hosts) == 1 {
		auth = hosts[0]
	}
	if auth == "" {
		res.Why = WhyNoHost
		return res, false
	}
	host := hostOnly(auth)
	name, ok, _ := normHost(host)
	if !ok {
		if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			res.Why = WhyIPHost
		} else {
			res.Why = WhyNoHost
		}
		return res, false
	}
	res.Name = name
	return res, false
}

func hasSchemePrefix(s, p string) bool {
	return len(s) >= len(p) && strings.EqualFold(s[:len(p)], p)
}

// hostOnly strips the port from host[:port] / [v6]:port.
func hostOnly(a string) string {
	if strings.HasPrefix(a, "[") {
		if j := strings.IndexByte(a, ']'); j >= 0 {
			return a[:j+1]
		}
		return a
	}
	if j := strings.LastIndexByte(a, ':'); j >= 0 && strings.Count(a, ":") == 1 {
		return a[:j]
	}
	return a
}

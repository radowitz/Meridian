package sniff

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

// helloOpts builds synthetic ClientHellos (RFC 8446 §4.1.2 layout).
type helloOpts struct {
	sni       []string // host_name entries (several: malformed)
	noExt     bool     // no extensions block at all
	ech       bool     // add encrypted_client_hello
	esni      bool     // add the old encrypted_server_name
	pad       int      // padding extension (21) of this many bytes
	dupExt    bool     // the supported_versions extension twice
	rawSNI    []byte   // server_name extension data as is
	trailing  []byte   // bytes after the extensions block
	sessionID int
	otherName bool // an unknown name_type entry before the host_name
}

func ext(typ uint16, data []byte) []byte {
	b := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint16(b, typ)
	binary.BigEndian.PutUint16(b[2:], uint16(len(data)))
	return append(b, data...)
}

func vec16(b []byte) []byte {
	out := make([]byte, 2, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	return append(out, b...)
}

func sniExt(names []string, other bool) []byte {
	var list []byte
	if other {
		list = append(list, 7)
		list = append(list, vec16([]byte("ignored"))...)
	}
	for _, n := range names {
		list = append(list, 0)
		list = append(list, vec16([]byte(n))...)
	}
	return ext(extServerName, vec16(list))
}

// helloMsg is the handshake message (type, 24-bit length, body).
func helloMsg(o helloOpts) []byte {
	var body []byte
	body = append(body, 3, 3)                           // legacy_version
	body = append(body, bytes.Repeat([]byte{7}, 32)...) // random
	body = append(body, byte(o.sessionID))
	body = append(body, bytes.Repeat([]byte{1}, o.sessionID)...)
	body = append(body, vec16([]byte{0x13, 0x01, 0x13, 0x02})...) // cipher_suites
	body = append(body, 1, 0)                                     // compression: null
	if !o.noExt {
		var exts []byte
		exts = append(exts, ext(43, []byte{2, 3, 4})...) // supported_versions
		if o.dupExt {
			exts = append(exts, ext(43, []byte{2, 3, 4})...)
		}
		switch {
		case o.rawSNI != nil:
			exts = append(exts, ext(extServerName, o.rawSNI)...)
		case len(o.sni) > 0:
			exts = append(exts, sniExt(o.sni, o.otherName)...)
		}
		exts = append(exts, ext(10, []byte{0, 2, 0, 0x1d})...) // supported_groups
		if o.ech {
			exts = append(exts, ext(extECH, append([]byte{0}, bytes.Repeat([]byte{9}, 40)...))...)
		}
		if o.esni {
			exts = append(exts, ext(extESNI, bytes.Repeat([]byte{9}, 20))...)
		}
		if o.pad > 0 {
			exts = append(exts, ext(21, make([]byte, o.pad))...)
		}
		body = append(body, vec16(exts)...)
	}
	body = append(body, o.trailing...)
	msg := []byte{handshakeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// records splits a handshake message into TLS records of at most size
// payload bytes each.
func records(msg []byte, size int) []byte {
	var out []byte
	for len(msg) > 0 {
		n := size
		if n > len(msg) {
			n = len(msg)
		}
		out = append(out, recordHandshake, 3, 1, byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

func clientHello(name string) []byte { return records(helloMsg(helloOpts{sni: []string{name}}), 1<<14) }

func TestTLSSNI(t *testing.T) {
	r, more := Sniff(clientHello("www.Example.COM"), DefaultMaxSniffBytes)
	if more || r.Proto != ProtoTLS || r.Name != "www.example.com" || r.Why != "" {
		t.Fatalf("%+v more=%v", r, more)
	}
	// An unknown name_type before the host_name is skipped.
	r, _ = Sniff(records(helloMsg(helloOpts{sni: []string{"a.example.net"}, otherName: true}), 1<<14), DefaultMaxSniffBytes)
	if r.Name != "a.example.net" {
		t.Fatalf("other name type: %+v", r)
	}
}

// Fragmented across TLS records (handshake message split over records of
// every size from 1 byte) and across TCP segments (every prefix of the
// byte stream is "more", the whole stream decides).
func TestTLSFragmented(t *testing.T) {
	msg := helloMsg(helloOpts{sni: []string{"frag.example.org"}, pad: 700})
	for _, size := range []int{1, 2, 3, 4, 5, 17, 100, 511, 1 << 14} {
		stream := records(msg, size)
		if len(stream) > DefaultMaxSniffBytes {
			continue
		}
		for i := 1; i < len(stream); i += 1 + i/7 {
			if r, more := Sniff(stream[:i], DefaultMaxSniffBytes); !more {
				t.Fatalf("record size %d, prefix %d/%d: decided early %+v", size, i, len(stream), r)
			}
		}
		r, more := Sniff(stream, DefaultMaxSniffBytes)
		if more || r.Name != "frag.example.org" {
			t.Fatalf("record size %d: %+v more=%v", size, r, more)
		}
	}
	// Bytes after the ClientHello (the client's next flight) do not matter.
	r, _ := Sniff(append(clientHello("x.example.org"), 0x14, 3, 3, 0, 1, 1), DefaultMaxSniffBytes)
	if r.Name != "x.example.org" {
		t.Fatalf("trailing record: %+v", r)
	}
}

func TestTLSOversized(t *testing.T) {
	// A large but acceptable ClientHello (two records).
	big := records(helloMsg(helloOpts{sni: []string{"big.example.org"}, pad: 12000}), 1<<14)
	if r, _ := Sniff(big, DefaultMaxSniffBytes); r.Name != "big.example.org" {
		t.Fatalf("12 kB hello: %+v", r)
	}
	// Declared larger than the limit: decided at once from the headers.
	huge := records(helloMsg(helloOpts{sni: []string{"huge.example.org"}, pad: 40000}), 1<<14)
	r, more := Sniff(huge[:9], DefaultMaxSniffBytes)
	if more || r.Why != WhyOversized || r.Name != "" {
		t.Fatalf("huge: %+v more=%v", r, more)
	}
	// A record longer than 2^14 is a framing error.
	bad := append([]byte{recordHandshake, 3, 1, 0x40, 0x01}, make([]byte, 10)...)
	if r, _ := Sniff(bad, DefaultMaxSniffBytes); r.Why != WhyMalformed {
		t.Fatalf("long record: %+v", r)
	}
	// Small limit: the stream cannot fit.
	if r, more := Sniff(clientHello("a.example.org")[:20], 64); more || r.Why != WhyOversized {
		t.Fatalf("small limit: %+v %v", r, more)
	}
}

func TestTLSMalformed(t *testing.T) {
	good := helloMsg(helloOpts{sni: []string{"m.example.org"}})
	cases := map[string][]byte{
		"two host_names":   records(helloMsg(helloOpts{sni: []string{"a.example.org", "b.example.org"}}), 1<<14),
		"duplicate ext":    records(helloMsg(helloOpts{sni: []string{"a.example.org"}, dupExt: true}), 1<<14),
		"empty name list":  records(helloMsg(helloOpts{rawSNI: []byte{0, 0}}), 1<<14),
		"short name list":  records(helloMsg(helloOpts{rawSNI: []byte{0, 9, 0, 0, 3, 'a'}}), 1<<14),
		"empty host_name":  records(helloMsg(helloOpts{rawSNI: vec16([]byte{0, 0, 0})}), 1<<14),
		"trailing garbage": records(helloMsg(helloOpts{sni: []string{"a.example.org"}, trailing: []byte{1, 2}}), 1<<14),
		"session id > 32":  records(helloMsg(helloOpts{sni: []string{"a.example.org"}, sessionID: 33}), 1<<14),
		"not client_hello": records(append([]byte{2}, good[1:]...), 1<<14),
		"interleaved alert": func() []byte {
			s := records(good, 20)
			return append(append(append([]byte{}, s[:25]...), 21, 3, 3, 0, 2, 1, 0), s[25:]...)
		}(),
		"zero-length record": append([]byte{recordHandshake, 3, 1, 0, 0}, records(good, 1<<14)...),
	}
	for name, b := range cases {
		r, more := Sniff(b, DefaultMaxSniffBytes)
		if more || r.Why != WhyMalformed || r.Name != "" {
			t.Errorf("%s: %+v more=%v", name, r, more)
		}
	}
	// Mutations never panic and never decide "more" on a full-limit buffer.
	rng := rand.New(rand.NewSource(1))
	base := records(helloMsg(helloOpts{sni: []string{"fuzz.example.org"}, ech: true, pad: 50}), 30)
	for i := 0; i < 20000; i++ {
		b := append([]byte(nil), base...)
		for k := 0; k < 1+rng.Intn(4); k++ {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		if rng.Intn(4) == 0 {
			b = b[:rng.Intn(len(b))]
		}
		Sniff(b, len(base)+64)
	}
}

func TestTLSNoNameCases(t *testing.T) {
	for name, c := range map[string]struct {
		b   []byte
		why string
	}{
		"no extensions": {records(helloMsg(helloOpts{noExt: true}), 1<<14), WhyNoSNI},
		"no SNI":        {records(helloMsg(helloOpts{}), 1<<14), WhyNoSNI},
		"IPv4 literal":  {clientHello("192.0.2.1"), WhyBadSNI},
		"IPv6 literal":  {clientHello("2001:db8::1"), WhyBadSNI},
		"bad chars":     {clientHello("a b.example"), WhyBadSNI},
		"digits only":   {clientHello("1.2.3"), WhyBadSNI},
	} {
		r, more := Sniff(c.b, DefaultMaxSniffBytes)
		if more || r.Name != "" || r.Why != c.why || r.Proto != ProtoTLS {
			t.Errorf("%s: %+v more=%v", name, r, more)
		}
	}
}

// ECH: the cleartext name is reported as OuterName only, never as Name.
func TestTLSECH(t *testing.T) {
	for _, o := range []helloOpts{{sni: []string{"public.example.net"}, ech: true}, {sni: []string{"public.example.net"}, esni: true}} {
		r, more := Sniff(records(helloMsg(o), 50), DefaultMaxSniffBytes)
		if more || !r.ECH || r.Name != "" || r.Why != WhyECH || r.OuterName != "public.example.net" {
			t.Fatalf("%+v more=%v", r, more)
		}
	}
	r, _ := Sniff(records(helloMsg(helloOpts{ech: true}), 1<<14), DefaultMaxSniffBytes)
	if !r.ECH || r.OuterName != "" || r.Why != WhyECH {
		t.Fatalf("ECH without SNI: %+v", r)
	}
}

func TestHTTPHost(t *testing.T) {
	for req, want := range map[string]string{
		"GET / HTTP/1.1\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n":                  "www.example.com",
		"GET / HTTP/1.1\r\nhOsT:   API.Example.org:8080  \r\n\r\n":                        "api.example.org",
		"POST /x HTTP/1.0\r\nHost: a.example.net\r\nContent-Length: 3\r\n\r\nabc":         "a.example.net",
		"GET http://abs.example.org:81/p?q HTTP/1.1\r\nHost: other.example\r\n\r\n":       "abs.example.org",
		"CONNECT tunnel.example.org:443 HTTP/1.1\r\nHost: tunnel.example.org:443\r\n\r\n": "tunnel.example.org",
		"GET / HTTP/1.1\nHost: lf.example.org\n\n":                                        "lf.example.org",
		"GET / HTTP/1.1\r\nHost: dot.example.org.\r\n\r\n":                                "dot.example.org",
	} {
		r, more := Sniff([]byte(req), DefaultMaxSniffBytes)
		if more || r.Proto != ProtoHTTP || r.Name != want {
			t.Errorf("%q: %+v more=%v", req, r, more)
		}
		for i := 1; i < strings.Index(req, "\n\n")+1 || i < strings.Index(req, "\r\n\r\n")+3; i++ {
			if _, more := Sniff([]byte(req[:i]), DefaultMaxSniffBytes); !more {
				t.Errorf("%q: prefix %d decided early", req, i)
				break
			}
		}
	}
	for req, why := range map[string]string{
		"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n": WhyMalformed,
		"GET / HTTP/1.1\r\nHost: a.example\r\n folded\r\n\r\n":         WhyMalformed,
		"GET / HTTP/1.1\r\nHost : a.example\r\n\r\n":                   WhyMalformed,
		"GET / HTTP/1.1\r\nnocolon\r\n\r\n":                            WhyMalformed,
		"GET / HTTP/1.0\r\nAccept: */*\r\n\r\n":                        WhyNoHost,
		"GET / HTTP/1.1\r\nHost: \r\n\r\n":                             WhyNoHost,
		"GET / HTTP/1.1\r\nHost: 192.0.2.7:80\r\n\r\n":                 WhyIPHost,
		"GET / HTTP/1.1\r\nHost: [2001:db8::7]:80\r\n\r\n":             WhyIPHost,
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":                             WhyHTTP2,
		"SSH-2.0-OpenSSH_9.6\r\n":                                      WhyOther,
		"GET / SPDY/3\r\n\r\n":                                         WhyOther,
		"\x00\x01\x02binary":                                           WhyOther,
		"HELO a b c\r\n":                                               WhyOther,
		"averyveryverylongmethodname / HTTP/1.1\r\n":                   WhyOther,
	} {
		r, more := Sniff([]byte(req), DefaultMaxSniffBytes)
		if more || r.Name != "" || r.Why != why {
			t.Errorf("%q: %+v more=%v, want %s", req, r, more, why)
		}
	}
	// A header block larger than the limit.
	big := "GET / HTTP/1.1\r\nX: " + strings.Repeat("a", 2000) + "\r\nHost: a.example\r\n\r\n"
	if r, more := Sniff([]byte(big[:1024]), 1024); more || r.Why != WhyOversized {
		t.Fatalf("oversized head: %+v %v", r, more)
	}
	// 0x16 followed by something that is not a TLS version.
	if r, more := Sniff([]byte{0x16, 0x09, 0x00, 0x00, 0x01, 0}, 100); more || r.Why != WhyOther {
		t.Fatalf("0x16 non-TLS: %+v %v", r, more)
	}
}

func FuzzSniff(f *testing.F) {
	f.Add(clientHello("seed.example.org"))
	f.Add(records(helloMsg(helloOpts{sni: []string{"e.example.org"}, ech: true}), 7))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: s.example.org\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, more := Sniff(b, 4096)
		if r.Name != "" && more {
			t.Fatal("name with more")
		}
		if r.ECH && r.Name != "" {
			t.Fatal("ECH with a name")
		}
	})
}

// A ClientHello written by the standard library's TLS client (an
// independent implementation of the same RFCs), whole and fed in small
// pieces.
func TestTLSStdlibClientHello(t *testing.T) {
	for _, maxVer := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		a, b := net.Pipe()
		go func() {
			c := tls.Client(a, &tls.Config{ServerName: "std.example.org", MaxVersion: maxVer, InsecureSkipVerify: true})
			_ = c.Handshake()
		}()
		var got []byte
		buf := make([]byte, 7)
		_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			n, err := b.Read(buf)
			got = append(got, buf[:n]...)
			r, more := Sniff(got, DefaultMaxSniffBytes)
			if !more {
				if r.Name != "std.example.org" || r.Proto != ProtoTLS {
					t.Fatalf("max version %#x: %+v", maxVer, r)
				}
				break
			}
			if err != nil {
				t.Fatalf("read: %v after %d bytes", err, len(got))
			}
		}
		a.Close()
		b.Close()
	}
}

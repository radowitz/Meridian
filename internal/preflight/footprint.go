package preflight

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Footprint is what one node's compiled bundle would create on its host.
// It is derived from the rendered files only (FootprintOf), so it describes
// exactly what the install would do, not what the topology intends.
type Footprint struct {
	Files      []string       `json:"files"`
	Interfaces []IfacePlan    `json:"interfaces"`
	Listens    []ListenPlan   `json:"listens"`
	Routes     []RoutePlan    `json:"routes"`
	Rules      []RulePlan     `json:"rules"`
	Tables     []int          `json:"route_tables"`
	TableNames map[int]string `json:"route_table_names"`
	NFTTables  []string       `json:"nft_tables"`
	Marks      []string       `json:"fwmarks"`
	Units      []string       `json:"units"`
	// Packages are the Debian packages the install script installs when the
	// command is missing; Binaries must already exist (wstunnel is never
	// installed by the panel).
	Packages []PackagePlan `json:"packages"`
	Binaries []string      `json:"binaries"`
	// Forwarding: the install turns on IPv4 / IPv6 forwarding.
	Forward4 bool `json:"forward4"`
	Forward6 bool `json:"forward6"`
	// SysctlAll: the routes script sets rp_filter=2 and disables redirects
	// on every interface.
	SysctlAll bool `json:"sysctl_all"`
	// Docker: the bundle runs containers (Mesh sidecar, unlock probe); they
	// are optional and need Docker already installed.
	Docker bool `json:"docker"`
	// DNS: the bundle carries /etc/smartdns/smartdns.conf.
	DNS bool `json:"dns"`
	// LoAddrs are the transit addresses the scripts put on lo
	// ("ip addr replace … dev lo").
	LoAddrs []netip.Prefix `json:"lo_addrs"`
}

// IfacePlan is a WireGuard interface the bundle brings up.
type IfacePlan struct {
	Name       string         `json:"name"`
	ListenPort int            `json:"listen_port,omitempty"`
	Addresses  []netip.Prefix `json:"addresses"`
}

// ListenPlan is a socket the bundle binds.
type ListenPlan struct {
	Proto    string     `json:"proto"`
	Addr     netip.Addr `json:"addr"`
	Wildcard bool       `json:"wildcard"`
	Port     int        `json:"port"`
	Owner    string     `json:"owner"` // interface, unit or smartdns
}

// RoutePlan is a route a script installs.
type RoutePlan struct {
	Family    int          `json:"family"`
	Dst       netip.Prefix `json:"dst"`
	Dev       string       `json:"dev,omitempty"`
	Table     int          `json:"table,omitempty"` // 0 = main
	Blackhole bool         `json:"blackhole,omitempty"`
	Metric    int          `json:"metric,omitempty"`
}

// RulePlan is a policy rule a script installs.
type RulePlan struct {
	Family   int    `json:"family"`
	Priority int    `json:"priority"`
	Selector string `json:"selector"`
	Table    string `json:"table,omitempty"`
	Fwmark   string `json:"fwmark,omitempty"`
}

// PackagePlan: the package that provides Command.
type PackagePlan struct {
	Package string `json:"package"`
	Command string `json:"command"`
}

var (
	reListenPort = regexp.MustCompile(`(?m)^\s*ListenPort\s*=\s*([0-9]+)\s*$`)
	reAddress    = regexp.MustCompile(`(?m)^\s*Address\s*=\s*(.+)$`)
	reWSServer   = regexp.MustCompile(`wstunnel server .*?\bwss?://(\[[0-9a-fA-F:.]+\]|[0-9.]+|localhost):([0-9]+)`)
	reWSClient   = regexp.MustCompile(`-L\s+'?(udp|tcp)://(\[[0-9a-fA-F:.]+\]|[0-9.]+):([0-9]+):`)
	reBind       = regexp.MustCompile(`(?m)^\s*(bind|bind-tcp|bind-tls|bind-https)\s+(\S+)`)
	reNFTTable   = regexp.MustCompile(`(?m)^\s*table (inet|ip|ip6|arp|bridge|netdev) ([A-Za-z0-9_]+) \{`)
	reRTLine     = regexp.MustCompile(`(?m)^([0-9]+)\s+([A-Za-z0-9_.-]+)`)
	reRouteCmd   = regexp.MustCompile(`(?m)^\s*ip (-6 )?route (?:replace|add) (.+)$`)
	reRuleCmd    = regexp.MustCompile(`(?m)^\s*ip (-6 )?rule add (.+?) priority ([0-9]+)\s*$`)
	reMark       = regexp.MustCompile(`\b(?:fwmark|mark set|meta mark set)\s+(0x[0-9a-fA-F]+)`)
	reLoAddr     = regexp.MustCompile(`(?m)^\s*ip (?:-6 )?addr (?:replace|add) '?([0-9a-fA-F:./]+)'? dev '?lo'?\s*$`)
	reForward4   = regexp.MustCompile(`(?m)^\s*net\.ipv4\.ip_forward\s*=\s*1`)
	reForward6   = regexp.MustCompile(`(?m)^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1`)
)

// FootprintOf derives the footprint from one node's host files (absolute
// paths, as provision.FilesFor returns them).
func FootprintOf(files map[string]string) Footprint {
	fp := Footprint{TableNames: map[int]string{}, Files: []string{}, Interfaces: []IfacePlan{}, Listens: []ListenPlan{},
		Routes: []RoutePlan{}, Rules: []RulePlan{}, Tables: []int{}, NFTTables: []string{}, Marks: []string{}, Units: []string{},
		Packages: []PackagePlan{}, Binaries: []string{}, LoAddrs: []netip.Prefix{}}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	tables := map[int]bool{}
	marks := map[string]bool{}
	addTable := func(n int) {
		if n > 0 && n != 253 && n != 254 && n != 255 {
			tables[n] = true
		}
	}
	wstunnel := false
	for _, p := range paths {
		body := files[p]
		fp.Files = append(fp.Files, p)
		dir, base := splitDir(p)
		switch {
		case dir == "/etc/wireguard" && strings.HasSuffix(base, ".conf"):
			ip := IfacePlan{Name: strings.TrimSuffix(base, ".conf"), Addresses: []netip.Prefix{}}
			if m := reListenPort.FindStringSubmatch(body); m != nil {
				ip.ListenPort, _ = strconv.Atoi(m[1])
				fp.Listens = append(fp.Listens, ListenPlan{Proto: "udp", Addr: netip.IPv6Unspecified(), Wildcard: true, Port: ip.ListenPort, Owner: ip.Name})
			}
			for _, m := range reAddress.FindAllStringSubmatch(body, -1) {
				for _, a := range strings.Split(m[1], ",") {
					if pr, err := netip.ParsePrefix(strings.TrimSpace(a)); err == nil {
						ip.Addresses = append(ip.Addresses, pr)
					}
				}
			}
			fp.Interfaces = append(fp.Interfaces, ip)
		case dir == "/etc/systemd/system" && (strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".timer")):
			fp.Units = append(fp.Units, base)
			if strings.HasPrefix(base, "wstunnel-") {
				wstunnel = true
			}
			if m := reWSServer.FindStringSubmatch(body); m != nil {
				if l, ok := listenOf("tcp", m[1], m[2], base); ok {
					fp.Listens = append(fp.Listens, l)
				}
			}
			for _, m := range reWSClient.FindAllStringSubmatch(body, -1) {
				if l, ok := listenOf(m[1], m[2], m[3], base); ok {
					fp.Listens = append(fp.Listens, l)
				}
			}
		case p == "/etc/smartdns/smartdns.conf":
			fp.DNS = true
			for _, m := range reBind.FindAllStringSubmatch(body, -1) {
				proto := "udp"
				if m[1] != "bind" {
					proto = "tcp"
				}
				spec := m[2]
				i := strings.LastIndex(spec, ":")
				if i < 0 {
					continue
				}
				host, port := spec[:i], spec[i+1:]
				if host == "" {
					host = "::"
				}
				if k := strings.Index(port, "@"); k >= 0 {
					port = port[:k]
				}
				if l, ok := listenOf(proto, host, port, "smartdns"); ok {
					fp.Listens = append(fp.Listens, l)
				}
			}
		case p == "/etc/iproute2/rt_tables.d/meridian.conf":
			for _, m := range reRTLine.FindAllStringSubmatch(body, -1) {
				n, _ := strconv.Atoi(m[1])
				addTable(n)
				fp.TableNames[n] = m[2]
			}
		case p == "/etc/meridian/forwarding.conf":
			fp.Forward4 = fp.Forward4 || reForward4.MatchString(body)
			fp.Forward6 = fp.Forward6 || reForward6.MatchString(body)
		case p == "/etc/meridian/mesh-sidecar.compose.yml":
			fp.Docker = true
		}
		if strings.HasSuffix(p, ".nft") || strings.HasSuffix(p, ".sh") {
			for _, m := range reNFTTable.FindAllStringSubmatch(body, -1) {
				t := m[1] + " " + m[2]
				if !containsStr(fp.NFTTables, t) {
					fp.NFTTables = append(fp.NFTTables, t)
				}
			}
			for _, m := range reMark.FindAllStringSubmatch(body, -1) {
				marks[strings.ToLower(m[1])] = true
			}
		}
		if strings.HasSuffix(p, ".sh") {
			for _, m := range reLoAddr.FindAllStringSubmatch(body, -1) {
				if pr, err := netip.ParsePrefix(m[1]); err == nil && !containsPrefix(fp.LoAddrs, pr) {
					fp.LoAddrs = append(fp.LoAddrs, pr)
				}
			}
			if strings.Contains(body, "harden_sysctl") {
				fp.SysctlAll = true
			}
			if strings.Contains(body, "docker run") || strings.Contains(body, "docker compose") {
				fp.Docker = true
			}
			for _, m := range reRouteCmd.FindAllStringSubmatch(body, -1) {
				if rp, ok := routeOf(m[1] != "", m[2]); ok {
					addTable(rp.Table)
					fp.Routes = appendRoute(fp.Routes, rp)
				}
			}
			for _, m := range reRuleCmd.FindAllStringSubmatch(body, -1) {
				prio, _ := strconv.Atoi(m[3])
				fam := 4
				if m[1] != "" {
					fam = 6
				}
				sel := strings.ReplaceAll(strings.ReplaceAll(m[2], "'", ""), `"`, "")
				ru := RulePlan{Family: fam, Priority: prio, Selector: sel}
				f := strings.Fields(sel)
				for j := 0; j+1 < len(f); j++ {
					switch f[j] {
					case "lookup", "table":
						ru.Table = f[j+1]
						if n, err := strconv.Atoi(f[j+1]); err == nil {
							addTable(n)
						}
					case "fwmark":
						ru.Fwmark = strings.ToLower(f[j+1])
					}
				}
				if !strings.Contains(sel, "$") && !hasRule(fp.Rules, ru) {
					fp.Rules = append(fp.Rules, ru)
				}
			}
		}
	}
	// Variable fwmarks ("fwmark $m") are not literal; the literal marks of
	// the nft files and scripts are.
	for m := range marks {
		fp.Marks = append(fp.Marks, m)
	}
	sort.Strings(fp.Marks)
	for n := range tables {
		fp.Tables = append(fp.Tables, n)
	}
	sort.Ints(fp.Tables)
	sort.Strings(fp.NFTTables)
	fp.Packages = append(fp.Packages,
		PackagePlan{Package: "wireguard-tools", Command: "wg"},
		PackagePlan{Package: "nftables", Command: "nft"},
		PackagePlan{Package: "iproute2", Command: "ip"})
	if fp.DNS {
		fp.Packages = append(fp.Packages, PackagePlan{Package: "smartdns", Command: "smartdns"})
	}
	if wstunnel {
		fp.Binaries = append(fp.Binaries, "wstunnel")
	}
	return fp
}

func containsPrefix(ps []netip.Prefix, p netip.Prefix) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

func appendRoute(rs []RoutePlan, r RoutePlan) []RoutePlan {
	for _, x := range rs {
		if x == r {
			return rs
		}
	}
	return append(rs, r)
}

func hasRule(rs []RulePlan, r RulePlan) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

func listenOf(proto, host, port, owner string) (ListenPlan, bool) {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return ListenPlan{}, false
	}
	l := ListenPlan{Proto: proto, Port: n, Owner: owner}
	switch host {
	case "", "::", "0.0.0.0", "*":
		l.Wildcard = true
		l.Addr = netip.IPv6Unspecified()
		if host == "0.0.0.0" {
			l.Addr = netip.IPv4Unspecified()
		}
	case "localhost":
		l.Addr = netip.MustParseAddr("127.0.0.1")
	default:
		a, err := netip.ParseAddr(host)
		if err != nil {
			return ListenPlan{}, false
		}
		l.Addr = a
	}
	return l, true
}

// routeOf reads the arguments of "ip route replace …" from a rendered
// script. Arguments with shell variables are skipped (they are runtime
// choices of the failover script, already covered by its static routes).
func routeOf(v6 bool, args string) (RoutePlan, bool) {
	args = strings.ReplaceAll(strings.ReplaceAll(args, "'", ""), `"`, "")
	if i := strings.IndexAny(args, "|&;>"); i >= 0 {
		args = args[:i]
	}
	f := strings.Fields(args)
	if len(f) == 0 {
		return RoutePlan{}, false
	}
	rp := RoutePlan{Family: 4}
	if v6 {
		rp.Family = 6
	}
	i := 0
	switch f[0] {
	case "blackhole", "unreachable", "prohibit":
		rp.Blackhole = true
		i++
	case "local", "broadcast", "throw":
		return RoutePlan{}, false
	}
	if i >= len(f) {
		return RoutePlan{}, false
	}
	switch {
	case f[i] == "default":
		if rp.Family == 4 {
			rp.Dst = netip.MustParsePrefix("0.0.0.0/0")
		} else {
			rp.Dst = netip.MustParsePrefix("::/0")
		}
	case strings.Contains(f[i], "$"):
		return RoutePlan{}, false
	default:
		p, ok := parsePrefixOrAddr(f[i])
		if !ok {
			return RoutePlan{}, false
		}
		rp.Dst = p
	}
	for j := i + 1; j+1 < len(f); j++ {
		switch f[j] {
		case "dev":
			if strings.Contains(f[j+1], "$") {
				return RoutePlan{}, false
			}
			rp.Dev = f[j+1]
		case "table":
			n, err := strconv.Atoi(f[j+1])
			if err != nil {
				return RoutePlan{}, false
			}
			rp.Table = n
		case "metric":
			rp.Metric, _ = strconv.Atoi(f[j+1])
		}
	}
	if rp.Table == 254 {
		rp.Table = 0
	}
	return rp, true
}

func splitDir(p string) (string, string) {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return "/", strings.TrimPrefix(p, "/")
	}
	return p[:i], p[i+1:]
}

// BundleDigest identifies exactly what an install would write: the node's
// files (with the private-key placeholder, before injection), in path
// order. A preflight is bound to it; a topology change that alters the
// node's files makes a stored preflight unusable.
func BundleDigest(files map[string]string) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	h := sha256.New()
	h.Write([]byte("meridian-bundle 1\n"))
	for _, p := range paths {
		sum := sha256.Sum256([]byte(files[p]))
		h.Write([]byte(p + "\x00" + hex.EncodeToString(sum[:]) + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Package preflight is the read-only conflict check that runs before the
// panel changes a host: a remote node's first install or update (over the
// pinned SSH channel, Script) and the gateway install (through
// meridian-host's fixed preflight action, which emits the same report).
//
// The flow is script → report → evaluation:
//
//   - Script is one fixed, reviewed bash script. Its only arguments are the
//     host paths the node's bundle would write (ValidatePaths); it changes
//     nothing on the host and prints a line-oriented report bounded to
//     MaxReport bytes.
//   - Parse reads that report. It tolerates garbage, truncation, oversized
//     and hostile output: a report without its header or end line is marked
//     incomplete (a blocking finding), every value is cleaned and capped.
//   - FootprintOf derives what the compiled bundle for the node would create
//     (interfaces, listen ports, addresses, routes, rules, tables, nft
//     tables, files, units, packages), and Evaluate turns report + footprint
//     into findings with a severity, a stable code, a Chinese message that
//     says what was found and what to do, and the affected resource.
//
// The package has no I/O of its own and imports no other Meridian package.
package preflight

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Report format version (first line "meridian-preflight 1").
const (
	Header    = "meridian-preflight 1"
	EndMarker = "meridian-preflight-end"
	// MaxReport is the largest report accepted; the script cuts its own
	// output at MaxReport+1 bytes so a longer answer is recognisable.
	MaxReport = 256 << 10
	// maxLines and maxField bound what the parser keeps.
	maxLines = 6000
	maxField = 400
	maxItems = 800
)

// Policy is one iptables/ip6tables built-in chain policy (-P lines).
type Policy struct {
	Family string `json:"family"` // ipv4 | ipv6
	Chain  string `json:"chain"`
	Policy string `json:"policy"`
}

// Addr is an address configured on an interface.
type Addr struct {
	Iface  string       `json:"iface"`
	Prefix netip.Prefix `json:"prefix"`
}

// Route is one route of the main table.
type Route struct {
	Family int          `json:"family"`
	Type   string       `json:"type,omitempty"` // "" (unicast), blackhole, unreachable, prohibit, throw
	Dst    netip.Prefix `json:"dst"`
	Dev    string       `json:"dev,omitempty"`
	Metric int          `json:"metric"`
	Raw    string       `json:"raw"`
}

// Rule is one policy routing rule.
type Rule struct {
	Family   int    `json:"family"`
	Priority int    `json:"priority"`
	Not      bool   `json:"not,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Fwmark   string `json:"fwmark,omitempty"`
	Iif      string `json:"iif,omitempty"`
	Oif      string `json:"oif,omitempty"`
	Table    string `json:"table,omitempty"`
	Action   string `json:"action,omitempty"` // unreachable, blackhole, prohibit, goto …
	Raw      string `json:"raw"`
}

// Listener is a listening TCP or bound UDP socket.
type Listener struct {
	Proto    string     `json:"proto"` // tcp | udp
	Addr     netip.Addr `json:"addr"`  // unspecified for 0.0.0.0, [::] and *
	Wildcard bool       `json:"wildcard"`
	Port     int        `json:"port"`
	Process  string     `json:"process,omitempty"`
	PID      int        `json:"pid,omitempty"`
	// Cgroup is the socket's cgroup ("ss --cgroup", read through
	// sock_diag: it needs no access to the owning process, unlike the
	// process name). It names the systemd unit or container that opened
	// the socket.
	Cgroup string `json:"cgroup,omitempty"`
	Raw    string `json:"raw"`
}

// Container is a container the report names by its fixed name.
type Container struct {
	ID      string `json:"id"`
	Running bool   `json:"running"`
}

// Chain is an nft base chain (or a regular chain: Hook empty).
type Chain struct {
	Table    string `json:"table"` // "family name"
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	Hook     string `json:"hook,omitempty"`
	Priority string `json:"priority,omitempty"`
	Policy   string `json:"policy,omitempty"`
}

// UnitState is what systemctl reported for one unit.
type UnitState struct {
	Active  string `json:"active"`
	Enabled string `json:"enabled"`
	MainPID int    `json:"main_pid,omitempty"`
}

// PathInfo is what the script saw at one requested path. Content is never
// reported: only the type, the size, whether the first lines mention
// Meridian and a SHA-256.
type PathInfo struct {
	Exists bool   `json:"exists"`
	Type   string `json:"type,omitempty"` // file | dir | link | other
	Size   int64  `json:"size,omitempty"`
	Marker bool   `json:"marker,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// NodeManifest is the ownership record a successful remote provision leaves
// at /var/lib/meridian/node/manifest (see internal/provision).
type NodeManifest struct {
	Node       string            `json:"node"`
	Deployment string            `json:"deployment"`
	Server     string            `json:"server,omitempty"`
	Bundle     string            `json:"bundle,omitempty"`
	Installed  int64             `json:"installed,omitempty"`
	Files      map[string]string `json:"files"` // path → sha256
	Orphans    []string          `json:"orphans,omitempty"`
	Interfaces []string          `json:"interfaces"`
	Units      []string          `json:"units"`
	NFTTables  []string          `json:"nft_tables"`
	Tables     []int             `json:"route_tables"`
	Packages   []string          `json:"packages,omitempty"`
}

// NodeJournal is the provision journal at /var/lib/meridian/node/journal.
type NodeJournal struct {
	State      string   `json:"state"` // running | done | compensated | incomplete
	Node       string   `json:"node,omitempty"`
	Deployment string   `json:"deployment,omitempty"`
	Run        string   `json:"run,omitempty"`
	Leftovers  []string `json:"leftovers,omitempty"`
}

// Report is the parsed preflight answer.
type Report struct {
	// Complete is false when the header or the end line is missing or the
	// answer is longer than MaxReport: nothing in it can be relied on to be
	// exhaustive.
	Complete  bool     `json:"complete"`
	Truncated bool     `json:"truncated,omitempty"`
	Notes     []string `json:"notes,omitempty"`
	Ignored   int      `json:"ignored_lines,omitempty"`

	UID          int             `json:"uid"`
	Arch         string          `json:"arch,omitempty"`
	Kernel       string          `json:"kernel,omitempty"`
	OSID         string          `json:"os_id,omitempty"`
	OSVersion    string          `json:"os_version,omitempty"`
	OSCodename   string          `json:"os_codename,omitempty"`
	OSPretty     string          `json:"os_pretty,omitempty"`
	Systemd      string          `json:"systemd,omitempty"` // yes | no
	MemTotalKB   int64           `json:"mem_total_kb"`
	MemAvailKB   int64           `json:"mem_avail_kb"`
	DiskAvailKB  int64           `json:"disk_avail_kb"`
	Commands     map[string]bool `json:"commands"`
	Iptables     string          `json:"iptables_version,omitempty"`
	Policies     []Policy        `json:"policies"`
	Sysctl       map[string]string
	Links        []string             `json:"links"`
	WGLinks      []string             `json:"wg_links"`
	WGPorts      map[string]int       `json:"wg_ports"`
	Addrs        []Addr               `json:"addrs"`
	Routes       []Route              `json:"routes"`
	Rules        []Rule               `json:"rules"`
	RTNames      map[int]string       `json:"rt_names"`
	TableRoutes  map[string]bool      `json:"table_routes"`  // table (as printed) → has routes
	TableDefault map[string]bool      `json:"table_default"` // table → has a default route
	Listeners    []Listener           `json:"listeners"`
	NFTTables    []string             `json:"nft_tables"`
	Chains       []Chain              `json:"chains"`
	Units        map[string]UnitState `json:"units"`
	NFTConf      string               `json:"nftables_conf,omitempty"` // flush | noflush | absent
	Procs        map[string]bool      `json:"procs"`
	Paths        map[string]PathInfo  `json:"paths"`
	Versions     map[string]string    `json:"versions"`
	Containers   map[string]Container `json:"containers"`
	Manifest     *NodeManifest        `json:"manifest,omitempty"`
	Journal      *NodeJournal         `json:"journal,omitempty"`
	Source       string               `json:"source,omitempty"`
}

func newReport() Report {
	return Report{
		UID: -1, MemTotalKB: -1, MemAvailKB: -1, DiskAvailKB: -1,
		Commands: map[string]bool{}, Sysctl: map[string]string{}, WGPorts: map[string]int{},
		RTNames: map[int]string{}, TableRoutes: map[string]bool{}, TableDefault: map[string]bool{},
		Units: map[string]UnitState{}, Procs: map[string]bool{}, Paths: map[string]PathInfo{},
		Versions: map[string]string{}, Containers: map[string]Container{}, Policies: []Policy{}, Links: []string{}, WGLinks: []string{},
		Addrs: []Addr{}, Routes: []Route{}, Rules: []Rule{}, Listeners: []Listener{}, NFTTables: []string{}, Chains: []Chain{},
	}
}

// Clean keeps printable text (no control characters, valid UTF-8), trims
// it and caps it at maxField runes. Exported for the host agent.
func Clean(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxField {
			break
		}
		switch {
		case r == '\t':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' || r == '‮' || r == '‭':
			continue
		default:
			b.WriteRune(r)
		}
		n++
	}
	return strings.TrimSpace(b.String())
}

// Line formats one report line (the host agent uses it so both sources
// emit the same format). Fields are cleaned; a field never contains a
// newline.
func Line(key string, fields ...string) string {
	parts := make([]string, 0, len(fields)+1)
	parts = append(parts, key)
	for _, f := range fields {
		parts = append(parts, Clean(f))
	}
	return strings.Join(parts, " ") + "\n"
}

// Parse reads a preflight report. It never fails: problems are recorded in
// Notes and make the report incomplete.
func Parse(text string) Report {
	r := newReport()
	if len(text) > MaxReport {
		r.Truncated = true
		text = text[:MaxReport]
		r.Notes = append(r.Notes, "报告超过上限，已截断")
	}
	lines := strings.Split(text, "\n")
	if len(lines) > maxLines {
		r.Truncated = true
		lines = lines[:maxLines]
		r.Notes = append(r.Notes, "报告行数超过上限，已截断")
	}
	header, end := false, false
	inManifest, inJournal := false, false
	var nftTable string
	var nftChain *Chain
	man := &NodeManifest{Files: map[string]string{}}
	jr := &NodeJournal{}
	manifestSeen, journalSeen := false, false
	for i, raw := range lines {
		line := Clean(strings.TrimRight(raw, "\r"))
		if line == "" {
			continue
		}
		if !header {
			if line == Header {
				header = true
				continue
			}
			// Anything before the header (a login banner, motd) is ignored.
			if i < 200 {
				r.Ignored++
				continue
			}
			break
		}
		if end {
			r.Ignored++
			continue
		}
		if line == EndMarker {
			end = true
			continue
		}
		key, rest, _ := strings.Cut(line, " ")
		rest = strings.TrimSpace(rest)
		f := strings.Fields(rest)
		switch key {
		case "uid":
			r.UID = atoi(rest, -1)
		case "arch":
			r.Arch = word(rest)
		case "kernel":
			r.Kernel = word(rest)
		case "os-id":
			r.OSID = strings.ToLower(strings.Trim(word(rest), `"'`))
		case "os-version":
			r.OSVersion = strings.Trim(word(rest), `"'`)
		case "os-codename":
			r.OSCodename = strings.Trim(word(rest), `"'`)
		case "os-pretty":
			r.OSPretty = strings.Trim(rest, `"'`)
		case "systemd":
			r.Systemd = word(rest)
		case "mem-total-kb":
			r.MemTotalKB = atoi64(rest, -1)
		case "mem-avail-kb":
			r.MemAvailKB = atoi64(rest, -1)
		case "disk-avail-kb":
			r.DiskAvailKB = atoi64(rest, -1)
		case "cmd":
			if len(f) == 2 && validName(f[0]) && len(r.Commands) < 64 {
				r.Commands[f[0]] = f[1] == "yes"
			}
		case "iptables-version":
			r.Iptables = rest
		case "ipt":
			// "ipt ipv4 -P FORWARD DROP"
			if len(f) == 4 && (f[0] == "ipv4" || f[0] == "ipv6") && f[1] == "-P" && len(r.Policies) < 16 {
				r.Policies = append(r.Policies, Policy{Family: f[0], Chain: f[2], Policy: strings.ToUpper(f[3])})
			}
		case "sysctl":
			if len(f) == 2 && validSysctl(f[0]) && len(r.Sysctl) < 64 {
				r.Sysctl[f[0]] = f[1]
			}
		case "link":
			if len(f) >= 1 && validIface(ifname(f[0])) {
				r.Links = appendCapped(r.Links, ifname(f[0]))
			}
		case "wglink":
			if len(f) >= 1 && validIface(ifname(f[0])) {
				r.WGLinks = appendCapped(r.WGLinks, ifname(f[0]))
			}
		case "wgport":
			if len(f) == 2 && validIface(f[0]) {
				if p := atoi(f[1], -1); p > 0 && p < 65536 && len(r.WGPorts) < maxItems {
					r.WGPorts[f[0]] = p
				}
			}
		case "addr":
			if len(f) >= 2 && validIface(ifname(f[0])) && len(r.Addrs) < maxItems {
				if p, err := netip.ParsePrefix(f[1]); err == nil {
					r.Addrs = append(r.Addrs, Addr{Iface: ifname(f[0]), Prefix: p})
				} else if a, err := netip.ParseAddr(f[1]); err == nil {
					r.Addrs = append(r.Addrs, Addr{Iface: ifname(f[0]), Prefix: netip.PrefixFrom(a, a.BitLen())})
				}
			}
		case "route4", "route6":
			fam := 4
			if key == "route6" {
				fam = 6
			}
			if rt, ok := parseRoute(fam, rest); ok && len(r.Routes) < maxItems {
				r.Routes = append(r.Routes, rt)
			}
		case "rule4", "rule6":
			fam := 4
			if key == "rule6" {
				fam = 6
			}
			if ru, ok := parseRule(fam, rest); ok && len(r.Rules) < maxItems {
				r.Rules = append(r.Rules, ru)
			}
		case "rtname":
			if len(f) >= 2 {
				if id := atoi(f[0], -1); id >= 0 && id < 1<<31 && validName(f[1]) && len(r.RTNames) < maxItems {
					r.RTNames[id] = f[1]
				}
			}
		case "rtable4", "rtable6":
			if len(f) == 2 && validName(f[0]) && len(r.TableRoutes) < maxItems {
				r.TableRoutes[f[0]] = true
				if f[1] == "default" {
					r.TableDefault[f[0]] = true
				}
			}
		case "ss":
			if l, ok := parseSS(rest); ok && len(r.Listeners) < maxItems {
				r.Listeners = append(r.Listeners, l)
			}
		case "ssc":
			// "ss -Hlntu --cgroup": the same sockets with their cgroup. Merged
			// into the listener of the same protocol, address and port.
			if l, ok := parseSS(rest); ok && l.Cgroup != "" {
				merged := false
				for i := range r.Listeners {
					x := &r.Listeners[i]
					if x.Proto == l.Proto && x.Port == l.Port && x.Addr == l.Addr && x.Cgroup == "" {
						x.Cgroup, merged = l.Cgroup, true
						break
					}
				}
				if !merged && len(r.Listeners) < maxItems {
					r.Listeners = append(r.Listeners, l)
				}
			}
		case "container":
			// "container <name> <id|-> <running true|false>"
			if len(f) >= 2 && validName(f[0]) && len(r.Containers) < 16 {
				c := Container{}
				if isHexN(f[1], 64) {
					c.ID = f[1]
				}
				c.Running = len(f) >= 3 && f[2] == "true"
				r.Containers[f[0]] = c
			}
		case "nft":
			// Lines of "nft list chains": table / chain headers and the
			// "type … hook … priority …; policy …;" line of a base chain.
			switch {
			case len(f) >= 3 && f[0] == "table":
				nftTable = f[1] + " " + f[2]
				nftChain = nil
				if validName(f[1]) && validName(f[2]) && !containsStr(r.NFTTables, nftTable) && len(r.NFTTables) < 128 {
					r.NFTTables = append(r.NFTTables, nftTable)
				}
			case len(f) >= 2 && f[0] == "chain" && nftTable != "":
				if len(r.Chains) < maxItems && validName(f[1]) {
					r.Chains = append(r.Chains, Chain{Table: nftTable, Name: f[1]})
					nftChain = &r.Chains[len(r.Chains)-1]
				}
			case len(f) >= 2 && f[0] == "type" && nftChain != nil:
				parseChainType(nftChain, f)
			}
		case "unit":
			// "unit <name> <active> <enabled> <mainpid>"
			if len(f) >= 3 && validUnit(f[0]) && len(r.Units) < 128 {
				st := UnitState{Active: f[1], Enabled: f[2]}
				if len(f) >= 4 {
					st.MainPID = atoi(f[3], 0)
				}
				r.Units[f[0]] = st
			}
		case "nftables-conf":
			r.NFTConf = word(rest)
		case "proc":
			if len(f) == 2 && validName(f[0]) && len(r.Procs) < 32 {
				r.Procs[f[0]] = f[1] == "yes"
			}
		case "path":
			// "path <p> absent" | "path <p> <type> <size> <marker yes|no> <sha256|->"
			if len(f) >= 2 && ValidPath(f[0]) && len(r.Paths) < MaxPaths {
				pi := PathInfo{}
				if f[1] != "absent" {
					pi.Exists = true
					pi.Type = f[1]
					if len(f) >= 3 {
						pi.Size = atoi64(f[2], 0)
					}
					if len(f) >= 4 {
						pi.Marker = f[3] == "yes"
					}
					if len(f) >= 5 && isHex64(f[4]) {
						pi.SHA256 = f[4]
					}
				}
				r.Paths[f[0]] = pi
			}
		case "version", "candidate":
			if len(f) >= 1 && validName(f[0]) && len(r.Versions) < 16 {
				v := strings.TrimSpace(strings.TrimPrefix(rest, f[0]))
				name := f[0]
				if key == "candidate" {
					name += "-candidate"
				}
				r.Versions[name] = v
			}
		case "manifest-begin":
			inManifest, manifestSeen = true, true
		case "manifest-end":
			inManifest = false
		case "manifest":
			if inManifest {
				parseManifestLine(man, f)
			}
		case "journal-begin":
			inJournal, journalSeen = true, true
		case "journal-end":
			inJournal = false
		case "journal":
			if inJournal {
				parseJournalLine(jr, f, rest)
			}
		case "note":
			if len(r.Notes) < 32 {
				r.Notes = append(r.Notes, rest)
			}
		default:
			r.Ignored++
		}
	}
	if manifestSeen && man.Node != "" {
		r.Manifest = man
	} else if manifestSeen {
		r.Notes = append(r.Notes, "节点清单存在但无法读懂")
		r.Manifest = &NodeManifest{Files: map[string]string{}}
	}
	if journalSeen {
		if jr.State == "" {
			jr.State = "unreadable"
		}
		r.Journal = jr
	}
	switch {
	case !header:
		r.Notes = append(r.Notes, "没有预检报告头：远端没有按预期执行预检脚本")
	case !end:
		r.Truncated = true
		r.Notes = append(r.Notes, "预检报告没有结束行：输出不完整（被截断或中途失败）")
	}
	r.Complete = header && end && !r.Truncated
	sort.Strings(r.Links)
	sort.Strings(r.WGLinks)
	return r
}

func parseManifestLine(m *NodeManifest, f []string) {
	if len(f) < 2 {
		return
	}
	switch f[0] {
	case "node":
		if validName(f[1]) {
			m.Node = f[1]
		}
	case "deployment":
		if validName(f[1]) {
			m.Deployment = f[1]
		}
	case "server":
		if validName(f[1]) {
			m.Server = f[1]
		}
	case "bundle":
		if isHex64(f[1]) {
			m.Bundle = f[1]
		}
	case "installed":
		m.Installed = atoi64(f[1], 0)
	case "file":
		if ValidPath(f[1]) && len(m.Files) < MaxPaths {
			h := ""
			if len(f) >= 3 && isHex64(f[2]) {
				h = f[2]
			}
			m.Files[f[1]] = h
		}
	case "orphan":
		if ValidPath(f[1]) && len(m.Orphans) < MaxPaths {
			m.Orphans = append(m.Orphans, f[1])
		}
	case "iface":
		if validIface(f[1]) && len(m.Interfaces) < 128 {
			m.Interfaces = append(m.Interfaces, f[1])
		}
	case "unit":
		if validUnit(f[1]) && len(m.Units) < 128 {
			m.Units = append(m.Units, f[1])
		}
	case "nft":
		if len(f) >= 3 && validName(f[1]) && validName(f[2]) && len(m.NFTTables) < 16 {
			m.NFTTables = append(m.NFTTables, f[1]+" "+f[2])
		}
	case "table":
		if n := atoi(f[1], -1); n > 0 && len(m.Tables) < 128 {
			m.Tables = append(m.Tables, n)
		}
	case "pkg":
		if validName(f[1]) && len(m.Packages) < 32 {
			m.Packages = append(m.Packages, f[1])
		}
	}
}

func parseJournalLine(j *NodeJournal, f []string, rest string) {
	if len(f) < 2 {
		return
	}
	switch f[0] {
	case "state":
		if validName(f[1]) {
			j.State = f[1]
		}
	case "node":
		if validName(f[1]) {
			j.Node = f[1]
		}
	case "deployment":
		if validName(f[1]) {
			j.Deployment = f[1]
		}
	case "run":
		if validName(f[1]) {
			j.Run = f[1]
		}
	case "leftover":
		if len(j.Leftovers) < 64 {
			j.Leftovers = append(j.Leftovers, strings.TrimSpace(strings.TrimPrefix(rest, "leftover")))
		}
	}
}

var routeTypes = map[string]bool{"blackhole": true, "unreachable": true, "prohibit": true, "throw": true, "unicast": true}

// parseRoute reads one line of "ip route show table main".
func parseRoute(fam int, s string) (Route, bool) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return Route{}, false
	}
	rt := Route{Family: fam, Raw: s}
	i := 0
	if routeTypes[f[0]] {
		if f[0] != "unicast" {
			rt.Type = f[0]
		}
		i++
	} else if f[0] == "local" || f[0] == "broadcast" || f[0] == "multicast" || f[0] == "anycast" || f[0] == "nat" {
		return Route{}, false
	}
	if i >= len(f) {
		return Route{}, false
	}
	dst := f[i]
	switch {
	case dst == "default":
		if fam == 4 {
			rt.Dst = netip.MustParsePrefix("0.0.0.0/0")
		} else {
			rt.Dst = netip.MustParsePrefix("::/0")
		}
	default:
		p, ok := parsePrefixOrAddr(dst)
		if !ok {
			return Route{}, false
		}
		rt.Dst = p
	}
	for j := i + 1; j+1 < len(f); j++ {
		switch f[j] {
		case "dev":
			if validIface(f[j+1]) {
				rt.Dev = f[j+1]
			}
		case "metric":
			rt.Metric = atoi(f[j+1], 0)
		}
	}
	return rt, true
}

func parsePrefixOrAddr(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// parseRule reads one line of "ip rule show": "18100:	from 10.0.0.0/24 lookup 150".
func parseRule(fam int, s string) (Rule, bool) {
	prio, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Rule{}, false
	}
	p := atoi(strings.TrimSpace(prio), -1)
	if p < 0 {
		return Rule{}, false
	}
	ru := Rule{Family: fam, Priority: p, Raw: s}
	f := strings.Fields(rest)
	for j := 0; j < len(f); j++ {
		next := ""
		if j+1 < len(f) {
			next = f[j+1]
		}
		switch f[j] {
		case "not":
			ru.Not = true
		case "from":
			ru.From, j = next, j+1
		case "to":
			ru.To, j = next, j+1
		case "fwmark":
			ru.Fwmark, j = next, j+1
		case "iif":
			ru.Iif, j = next, j+1
		case "oif":
			ru.Oif, j = next, j+1
		case "lookup", "table":
			ru.Table, j = next, j+1
		case "unreachable", "blackhole", "prohibit":
			ru.Action = f[j]
		case "goto":
			ru.Action, j = "goto "+next, j+1
		}
	}
	return ru, true
}

// parseSS reads one line of "ss -Hlntup":
// "udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:* users:((\"x\",pid=1,fd=3))".
func parseSS(s string) (Listener, bool) {
	f := strings.Fields(s)
	if len(f) < 5 {
		return Listener{}, false
	}
	proto := strings.ToLower(f[0])
	if proto != "tcp" && proto != "udp" {
		return Listener{}, false
	}
	local := f[4]
	i := strings.LastIndex(local, ":")
	if i <= 0 {
		return Listener{}, false
	}
	host, port := local[:i], atoi(local[i+1:], -1)
	if port <= 0 || port > 65535 {
		return Listener{}, false
	}
	l := Listener{Proto: proto, Port: port, Raw: s}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if k := strings.Index(host, "%"); k >= 0 {
		host = host[:k]
	}
	switch host {
	case "*", "0.0.0.0", "::":
		l.Wildcard = true
		if host == "0.0.0.0" {
			l.Addr = netip.IPv4Unspecified()
		} else {
			l.Addr = netip.IPv6Unspecified()
		}
	default:
		a, err := netip.ParseAddr(host)
		if err != nil {
			return Listener{}, false
		}
		l.Addr = a.Unmap()
	}
	if k := strings.Index(s, "cgroup:"); k >= 0 {
		cg := s[k+len("cgroup:"):]
		if e := strings.IndexAny(cg, " \t"); e >= 0 {
			cg = cg[:e]
		}
		if validCgroup(cg) {
			l.Cgroup = cg
		}
	}
	if k := strings.Index(s, "users:((\""); k >= 0 {
		rest := s[k+len("users:((\""):]
		if e := strings.Index(rest, "\""); e > 0 {
			name := rest[:e]
			if validName(name) {
				l.Process = name
			}
		}
		if p := strings.Index(rest, "pid="); p >= 0 {
			num := rest[p+4:]
			if e := strings.IndexAny(num, ",)"); e > 0 {
				l.PID = atoi(num[:e], 0)
			}
		}
	}
	return l, true
}

func parseChainType(c *Chain, f []string) {
	// type filter hook forward priority filter; policy drop;
	for j := 0; j+1 < len(f); j++ {
		v := strings.TrimSuffix(f[j+1], ";")
		switch f[j] {
		case "type":
			c.Type = v
		case "hook":
			c.Hook = v
		case "priority":
			c.Priority = v
		case "policy":
			c.Policy = v
		}
	}
}

func word(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

func atoi(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func atoi64(s string, def int64) int64 {
	n, err := strconv.ParseInt(word(s), 10, 64)
	if err != nil {
		return def
	}
	return n
}

func appendCapped(s []string, v string) []string {
	if len(s) >= maxItems || containsStr(s, v) {
		return s
	}
	return append(s, v)
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func isHex64(s string) bool { return isHexN(s, 64) }

func isHexN(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validName: a short token of letters, digits and ._:@+- (table, process,
// command and unit-ish names as the tools print them).
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:@+-", c)) {
			return false
		}
	}
	return true
}

func validIface(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-@", c)) {
			return false
		}
	}
	return true
}

// validCgroup: an absolute cgroup path of unit-ish names.
func validCgroup(s string) bool {
	if len(s) < 2 || len(s) > 300 || s[0] != '/' || strings.Contains(s, "..") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/._:@+-\\", c)) {
			return false
		}
	}
	return true
}

// CgroupUnit is the systemd unit a cgroup path ends in ("" if none).
func CgroupUnit(cg string) string {
	base := cg[strings.LastIndex(cg, "/")+1:]
	if strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".scope") {
		return base
	}
	return ""
}

// CgroupContainer is the container id in a cgroup path
// (".../docker-<id>.scope" or ".../docker/<id>"), "" if none.
func CgroupContainer(cg string) string {
	for _, part := range strings.Split(cg, "/") {
		part = strings.TrimSuffix(strings.TrimPrefix(part, "docker-"), ".scope")
		if isHexN(part, 64) {
			return part
		}
	}
	return ""
}

// ifname drops the "@peer" suffix ip prints for veth and vlan links.
func ifname(s string) string {
	if i := strings.IndexByte(s, '@'); i > 0 {
		return s[:i]
	}
	return s
}

func validUnit(s string) bool {
	return validName(strings.ReplaceAll(s, "\\", "")) && strings.Contains(s, ".")
}

func validSysctl(s string) bool {
	if s == "" || len(s) > 96 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

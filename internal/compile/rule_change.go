package compile

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/radowitz/meridian/internal/lists"
)

// The allowlist of a rule change (the panel's automatic install of saved
// rules, service groups and rule-sets: internal/api/rules_autoapply.go).
//
// A rule change may touch only these gateway files, found from the real
// compiled output (TestRuleChangeAllowlist, rule_change_test.go):
//
// Whole files, nothing in them but the rule list's own products:
//   - etc/meridian/rules/order.conf  the rule manifest (lists.ManifestPath)
//   - etc/meridian/rules/decide.json the rule decision snapshot (DecidePath)
//   - the sniffing forwarder's target file (SniffTargetsPath), when present
//
// Mixed files, where only the rule sections may differ and every other
// line must be byte-identical (same lines, same order):
//   - etc/smartdns/smartdns.conf: the trailing rule section after the
//     "Rules in list order" header — per-rule comments, "domain-set -name
//     r<n>" and "domain-rules /domain-set:r<n>/" lines whose nameserver is
//     "domestic" or a group the unchanged part defines, and whose nftset
//     names only rule sets;
//   - etc/nftables.d/meridian.nft: the rule address sets ("set r<n>",
//     "r<n>6", "r<n>_6", "r<n>c", "r<n>c6") and, in chain classify, the
//     contiguous block of rule lines ("[sources] ip/ip6 daddr @<rule set>
//     meta mark set <mark> return", the mark one the unchanged part already
//     uses), the QUIC chain's per-rule exemption lines and the sniffing
//     forwarder's "resolver of the target file" accept lines (they follow
//     the sniff target file; their mark must be one already in use).
//
// A save of the unlock page (采用 / 手动, internal/api/unlock_matrix.go)
// may also change one region group's member order, mode, chosen member and
// failover. RuleChange then gets those group IDs, and in meridian.nft the
// group's comment lines "# group <id> mark M transit T target <exit> …"
// and "# default-exit <exit> group <id> mark M" may name another exit (mark
// and transit stay compared). The groups are switched on their hubs: a
// change of a hub's scripts is another node's file and is refused like any
// other, so the change then waits for a deploy.
//
// Everything else is refused: any other gateway file, any file of another
// node, a file added or removed, a header line or a server line of the
// resolver configuration, a mark or interface of the ruleset. An unknown
// line in a rule section is refused too, so a renderer change that adds a
// new kind of line fails closed until it is listed here.

// RuleWholeFiles are the node files a rule change may change entirely.
var RuleWholeFiles = []string{
	strings.TrimPrefix(lists.ManifestPath, "/"),
	strings.TrimPrefix(DecidePath, "/"),
	strings.TrimPrefix(SniffTargetsPath, "/"),
}

// Rule mixed files (node-relative).
const (
	RuleDNSFile = "etc/smartdns/smartdns.conf"
	RuleNFTFile = "etc/nftables.d/meridian.nft"
)

const ruleSetName = `r[0-9]+(?:6|_6|c|c6)?`

var (
	reNFTSetOpen  = regexp.MustCompile(`^  set ` + ruleSetName + ` \{$`)
	reNFTSetBody  = regexp.MustCompile(`^    (type (ipv4_addr|ipv6_addr)|flags interval(, timeout)?|elements = \{ [0-9a-fA-F.:/, ]+ \})$`)
	reNFTRuleLine = regexp.MustCompile(`^    (ether saddr [0-9a-fA-F:]+ )?((ip|ip6) saddr [0-9a-fA-F.:/]+ )?(ip|ip6) daddr @(` + ruleSetName + `|chnroute|chnroute6) meta mark set (0x[0-9a-f]+) return$`)
	reNFTQUICLine = regexp.MustCompile(`^    iifname \S+ udp dport 443 (ip|ip6) daddr @(` + ruleSetName + `|chnroute|chnroute6) return comment "above the QUIC switch: exempt"$`)
	reNFTSniffRes = regexp.MustCompile(`^    (ip|ip6) daddr [0-9a-fA-F.:]+ meta mark (0x[0-9a-f]+) meta l4proto \{ tcp, udp \} th dport 53 accept comment "resolver of the target file"$`)
	reNFTMarks    = regexp.MustCompile(`0x[0-9a-f]+`)
	reNFTGroupTgt = regexp.MustCompile(`^(# group (\S+) mark 0x[0-9a-f]+ transit \S+) target \S+((?: \S+)*)$`)
	reNFTDefExit  = regexp.MustCompile(`^# default-exit \S+ (group (\S+) mark 0x[0-9a-f]+)$`)

	reDNSComment = regexp.MustCompile(`^(# rule \S+ -> .*|# QUIC switch .*|# \S+ .* is installed in nft set ` + ruleSetName + `, not in SmartDNS|# no in-tunnel resolver; SOA so the query does not leave via another exit)$`)
	reDNSSet     = regexp.MustCompile(`^domain-set -name (r[0-9]+) -file /var/lib/meridian/geosite/ordered/(r[0-9]+)\.txt$`)
	reDNSSOA     = regexp.MustCompile(`^domain-rules /domain-set:r[0-9]+/ -address #$`)
	reDNSRule    = regexp.MustCompile(`^domain-rules /domain-set:r[0-9]+/ -nameserver (\S+)(?: -address #6| -address -6)? -nftset #4:inet#meridian#` + ruleSetName + `(?:,#6:inet#meridian#` + ruleSetName + `)?$`)
	reDNSGroup   = regexp.MustCompile(` -group (\S+)`)
)

const dnsRuleHeader = "# matches it, so SmartDNS's longest-name choice gives the same rule as list order."

// maskNFT returns the ruleset without its rule sections, or ok=false when
// a rule section holds a line that is not a known rule line.
func maskNFT(body string, groups map[string]bool) (string, bool) {
	lines := strings.Split(body, "\n")
	var out, ruleMarks []string
	inSet, inRun := false, false
	for _, l := range lines {
		if m := reNFTGroupTgt.FindStringSubmatch(l); m != nil && groups[m[2]] {
			l = m[1] + " target *" + m[3]
		} else if m := reNFTDefExit.FindStringSubmatch(l); m != nil && groups[m[2]] {
			l = "# default-exit * " + m[1]
		}
		switch {
		case inSet:
			if l == "  }" {
				inSet = false
				continue
			}
			if !reNFTSetBody.MatchString(l) {
				return "", false
			}
			continue
		case reNFTSetOpen.MatchString(l):
			inSet, inRun = true, false
			continue
		}
		if m := reNFTRuleLine.FindStringSubmatch(l); m != nil {
			// chnroute lines belong to a rule run only (GEOIP,CN rules):
			// the fixed chnroute lines after direct4/6 stay compared.
			if inRun || strings.HasPrefix(m[5], "r") {
				inRun = true
				ruleMarks = append(ruleMarks, m[6])
				continue
			}
		}
		if m := reNFTSniffRes.FindStringSubmatch(l); m != nil {
			// The sniffing forwarder may query the resolvers of the rules'
			// targets (they follow the sniff target file).
			inRun = true
			ruleMarks = append(ruleMarks, m[2])
			continue
		}
		if reNFTQUICLine.MatchString(l) {
			inRun = true
			continue
		}
		inRun = false
		out = append(out, l)
	}
	if inSet {
		return "", false
	}
	masked := strings.Join(out, "\n")
	// A rule may only use a mark the unchanged part already uses (a new
	// exit or group mark changes the routing, not just the rules).
	known := map[uint64]bool{0: true}
	for _, m := range reNFTMarks.FindAllString(masked, -1) {
		if v, err := strconv.ParseUint(m, 0, 64); err == nil {
			known[v] = true
		}
	}
	for _, m := range ruleMarks {
		v, err := strconv.ParseUint(m, 0, 64)
		if err != nil || !known[v] {
			return "", false
		}
	}
	return masked, true
}

// maskDNS returns the resolver configuration without its rule section.
func maskDNS(body string) (string, bool) {
	i := strings.Index(body, dnsRuleHeader+"\n")
	if i < 0 {
		// No rule section: the same form as a file whose rule section is
		// masked, so zero rules ↔ one rule compares equal.
		return strings.TrimRight(body, "\n"), true
	}
	head := body[:i+len(dnsRuleHeader)+1]
	groups := map[string]bool{"domestic": true}
	for _, m := range reDNSGroup.FindAllStringSubmatch(head, -1) {
		groups[m[1]] = true
	}
	for _, l := range strings.Split(body[len(head):], "\n") {
		switch {
		case l == "", reDNSComment.MatchString(l), reDNSSOA.MatchString(l):
		case reDNSSet.MatchString(l):
			m := reDNSSet.FindStringSubmatch(l)
			if m[1] != m[2] {
				return "", false
			}
		case reDNSRule.MatchString(l):
			if !groups[reDNSRule.FindStringSubmatch(l)[1]] {
				return "", false
			}
		default:
			return "", false
		}
	}
	// The rule section starts at its three-line comment block (the header
	// is its last line): drop exactly those lines so zero rules and some
	// rules mask alike. Only the two known lines above the header are
	// dropped; any other comment before them stays compared.
	pre := strings.Split(body[:i], "\n")
	pre = pre[:len(pre)-1] // body[:i] ends with "\n" (or is empty)
	if len(pre) < 2 || !strings.HasPrefix(pre[len(pre)-2], "# Rules in list order, first match wins.") ||
		!strings.HasSuffix(pre[len(pre)-1], "(meridian lists-derive): a name belongs to the first rule that") {
		return "", false
	}
	pre = pre[:len(pre)-2]
	return strings.TrimRight(strings.Join(pre, "\n"), "\n"), true
}

// RuleChange compares the compile of the installed rules (prev) with the
// compile of the saved ones (next), all else equal. changed lists the
// differing gateway files the allowlist accepts; refused every other
// difference (a bundle path, with "（规则以外的段落）" for a mixed file whose
// other sections differ). groups are the region groups whose selection the
// change may move (an unlock-page save); see the file comment.
func RuleChange(prev, next *Bundle, node string, groups ...string) (changed, refused []string) {
	base := "nodes/" + node + "/"
	allowed := map[string]bool{}
	for _, g := range groups {
		allowed[g] = true
	}
	whole := map[string]bool{}
	for _, f := range RuleWholeFiles {
		whole[base+f] = true
	}
	seen := map[string]bool{}
	visit := func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		a, inA := prev.Files[p]
		b, inB := next.Files[p]
		if inA && inB && a == b {
			return
		}
		if !inA || !inB {
			refused = append(refused, p)
			return
		}
		var mask func(string) (string, bool)
		switch p {
		case base + RuleDNSFile:
			mask = maskDNS
		case base + RuleNFTFile:
			mask = func(b string) (string, bool) { return maskNFT(b, allowed) }
		default:
			if whole[p] {
				changed = append(changed, p)
			} else {
				refused = append(refused, p)
			}
			return
		}
		ma, okA := mask(a)
		mb, okB := mask(b)
		if okA && okB && ma == mb {
			changed = append(changed, p)
			return
		}
		refused = append(refused, p+"（规则以外的段落）")
	}
	for p := range prev.Files {
		visit(p)
	}
	for p := range next.Files {
		visit(p)
	}
	sort.Strings(changed)
	sort.Strings(refused)
	return changed, refused
}

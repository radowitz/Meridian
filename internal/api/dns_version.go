package api

// Versions of the DNS account identifiers (docs/architecture.md「出口解析上游」,
// 「轮换账户标识」).
//
// An exit's SmartDNS config names its account only by the credential's
// placeholder, which stays the same when the value is rotated: on its own
// the node's files — and so the bundle digest everything is bound to —
// would not change, and a rotated exit would look in sync. The credential
// store therefore counts every value of a credential (its version: 1 when
// created, +1 per rotation; a counter in the index, nothing derived from
// the value), and compileWith writes that number into every SmartDNS
// config that carries a DNS account placeholder, as one comment line right
// after compile.ExitDNSRestrictedMarker. The version is then part of the
// node's files and of everything bound to them:
//
//   - the bundle digest a preflight is reviewed for (gateReviewed refuses
//     an install with a preflight from before the rotation);
//   - the per-node state (nodeStates: "changed") and the deployment guide
//     (an install step, never verify-only or adopted, since the host's
//     manifest records the old digest), whose plan version also folds the
//     versions in, so an open run goes stale;
//   - what an install records (provisionOutcome.InstalledDNSAccounts, and
//     the digest the host's manifest keeps), so the 解析配置 view can show
//     the planned and the installed version.
//
// Files that name no DNS account credential are not touched: a topology
// without an account in its exit upstream compiles byte-identically.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
)

// dnsAccountVersionMarker starts the line that carries the versions of the
// DNS account credentials a SmartDNS config names (comma separated, in the
// order of the credential ids). Never a value.
const dnsAccountVersionMarker = "# meridian-account-version: "

// dnsAccountIDsIn lists the DNS account credential ids whose placeholders
// body carries (sorted, unique).
func dnsAccountIDsIn(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range model.SecretPlaceholderRe.FindAllStringSubmatch(body, -1) {
		if id := m[1]; credentials.IsDNSAccountSecretID(id) && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// stampDNSAccountVersions adds the version line to a SmartDNS config that
// names DNS account credentials. A config that names none, or one whose
// credential has no known version (it does not exist: the install refuses
// it anyway), is returned unchanged.
func stampDNSAccountVersions(body string, versions map[string]int) string {
	ids := dnsAccountIDsIn(body)
	if len(ids) == 0 || !strings.Contains(body, compile.ExitDNSRestrictedMarker+"\n") {
		return body
	}
	vs := make([]string, 0, len(ids))
	for _, id := range ids {
		v, ok := versions[id]
		if !ok || v <= 0 {
			return body
		}
		vs = append(vs, strconv.Itoa(v))
	}
	line := dnsAccountVersionMarker + strings.Join(vs, ",") + " (version of the account identifier: +1 per rotation; not the identifier)\n"
	return strings.Replace(body, compile.ExitDNSRestrictedMarker+"\n", compile.ExitDNSRestrictedMarker+"\n"+line, 1)
}

// dnsAccountVersionsIn reads back the versions a stamped config carries:
// credential id → version (nil when it names none or is not stamped).
func dnsAccountVersionsIn(body string) map[string]int {
	ids := dnsAccountIDsIn(body)
	if len(ids) == 0 {
		return nil
	}
	_, rest, ok := strings.Cut(body, "\n"+dnsAccountVersionMarker)
	if !ok {
		return nil
	}
	rest, _, _ = strings.Cut(rest, " ")
	rest, _, _ = strings.Cut(rest, "\n")
	vs := strings.Split(rest, ",")
	if len(vs) != len(ids) {
		return nil
	}
	out := map[string]int{}
	for i, id := range ids {
		v, err := strconv.Atoi(vs[i])
		if err != nil || v <= 0 {
			return nil
		}
		out[id] = v
	}
	return out
}

// dnsAccountVersionsOf merges the versions every file of files carries
// (nil when none does).
func dnsAccountVersionsOf(files map[string]string) map[string]int {
	var out map[string]int
	for _, body := range files {
		for id, v := range dnsAccountVersionsIn(body) {
			if out == nil {
				out = map[string]int{}
			}
			out[id] = v
		}
	}
	return out
}

// stampDNSAccounts is the step of compileWith that writes the current
// version of each DNS account credential into the configs that name it.
// b is returned as is when nothing names one (or the credential store is
// not available: the install, which needs the store, refuses then anyway).
func (s *Server) stampDNSAccounts(b *compile.Bundle) *compile.Bundle {
	if b == nil {
		return b
	}
	seen := map[string]bool{}
	var ids []string
	for _, body := range b.Files {
		for _, id := range dnsAccountIDsIn(body) {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return b
	}
	cs, err := s.credStore()
	if err != nil {
		return b
	}
	vers := cs.DNSAccountVersions(ids)
	nb := *b
	nb.Files = make(map[string]string, len(b.Files))
	for p, body := range b.Files {
		nb.Files[p] = stampDNSAccountVersions(body, vers)
	}
	return &nb
}

// sameVersions reports whether two version maps are equal (nil and empty
// are).
func sameVersions(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// versionsText renders versions for a message: "dnsacct-… 版本 3、…".
func versionsText(m map[string]int) string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%s 版本 %d", id, m[id]))
	}
	return strings.Join(parts, "、")
}

// dnsAccountChangeReason explains a changed node whose files name DNS
// account credentials (planned): rotated since its install, or installed
// before versions were recorded. "" when the versions are not the reason.
func dnsAccountChangeReason(planned, installed map[string]int) string {
	switch {
	case len(planned) == 0:
		return ""
	case installed == nil:
		return "这个出口的解析上游引用 DNS 账户标识（现在是 " + versionsText(planned) + "），但它的安装记录没有账户标识的版本（在面板记录版本之前装的）：" +
			"无法确认装上去的是当前的值，按待下发处理；重新预检并安装后恢复一致"
	case !sameVersions(planned, installed):
		return "DNS 账户标识已轮换（已安装 " + versionsText(installed) + "，现在是 " + versionsText(planned) + "）：" +
			"出口仍在用旧的值，重新预检并安装后才用新的值"
	}
	return ""
}

// deployVersion is the deployment guide's plan version: the topology's,
// with the versions of the DNS account credentials b's files name folded
// in (unchanged when they name none), so a rotation makes an open run
// stale like a topology change.
func deployVersion(t model.Topology, b *compile.Bundle) string {
	v := topologyVersion(t)
	if b == nil {
		return v
	}
	vers := dnsAccountVersionsOf(b.Files)
	if len(vers) == 0 {
		return v
	}
	h := sha256.Sum256([]byte(v + "\n" + versionsText(vers)))
	return hex.EncodeToString(h[:])[:16]
}

// dnsAccountExits lists the managed exits whose resolver upstream names
// credential id (the global setting or their own), sorted.
func dnsAccountExits(t model.Topology, id string) []string {
	out := []string{}
	for _, n := range t.Nodes {
		if !n.Managed {
			continue
		}
		for _, c := range exitDNSCredentials(t, n.ID) {
			if c == id {
				out = append(out, n.ID)
			}
		}
	}
	sort.Strings(out)
	return out
}

package api

// Versions of the SOCKS credentials of external SOCKS exits
// (docs/architecture.md「轮换外部 SOCKS 凭据」).
//
// A carrier's redirector config (compile.ExtProxyConfig) names the proxy's
// username and password only by placeholders that stay the same when the
// credential is rotated: on its own the carrier's files — and the bundle
// digest everything is bound to — would not change, and a carrier would
// look in sync while it keeps the old username and password. As for the
// DNS account identifiers (dns_version.go), compileWith therefore writes
// the credential's version (a counter of the credential store: 1 when
// created, +1 per rotation, nothing derived from the material) into the
// config, as one comment line at the end of its leading comment block.
// The version is then part of the carrier's files and of everything bound
// to them: the bundle digest a preflight is reviewed for, the per-node
// state, the deployment guide and its plan version, the record of an
// install.
//
// Unlike the DNS accounts, external exits were deployed before versions
// existed, and a line in every carrier's config would turn every carrier
// into "pending" on upgrade. So only tracked credentials get one
// (credentials.SOCKSVersion.Tracked): those created after the store took
// its one-time baseline, and those of the baseline once they are rotated
// past it. A carrier whose credentials are all as the baseline found them
// compiles byte-identically to before, and so does every topology without
// an external exit; until the baseline is written nothing is tracked.
//
// What cannot be known is which value a carrier installed before the
// baseline was given: that install recorded no version. Such a carrier
// stays in sync and says so (socksUnrecordedNote); an install made by this
// version records the versions it applied (provisionOutcome.SOCKSVersions),
// for that carrier only.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/radowitz/meridian/internal/compile"
	"github.com/radowitz/meridian/internal/credentials"
	"github.com/radowitz/meridian/internal/model"
)

// socksVersionMarker starts the line that carries the versions of the
// tracked SOCKS credentials a redirector config names, as
// "<credential id>=<version>" separated by commas, in the order of the
// ids. Never a username or password.
const socksVersionMarker = "# meridian-socks-version: "

const socksVersionNote = " (version of the SOCKS credential: +1 per rotation; not the username or password)"

// isExtProxyConfig reports whether a bundle path ("nodes/<id>/etc/…") or a
// host path is a carrier's redirector config.
func isExtProxyConfig(p string) bool {
	return strings.HasSuffix("/"+strings.TrimPrefix(p, "/"), compile.ExtProxyConfig)
}

// socksCredIDsIn lists the SOCKS credential ids whose halves body names by
// placeholder (sorted, unique).
func socksCredIDsIn(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range model.SecretPlaceholderRe.FindAllStringSubmatch(body, -1) {
		if !credentials.IsSOCKSSecretID(m[1]) {
			continue
		}
		id := strings.TrimSuffix(strings.TrimSuffix(m[1], "-user"), "-pass")
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// stampSOCKSVersions adds the version line to a redirector config for the
// credentials it names that have a version in versions (the tracked ones).
// A config that names none of them is returned unchanged, byte for byte.
func stampSOCKSVersions(body string, versions map[string]int) string {
	if strings.Contains(body, socksVersionMarker) {
		return body
	}
	var parts []string
	for _, id := range socksCredIDsIn(body) {
		if v := versions[id]; v > 0 {
			parts = append(parts, id+"="+strconv.Itoa(v))
		}
	}
	if len(parts) == 0 {
		return body
	}
	// After the leading comment block (the file's own header).
	at := 0
	for at < len(body) && body[at] == '#' {
		nl := strings.IndexByte(body[at:], '\n')
		if nl < 0 {
			return body
		}
		at += nl + 1
	}
	return body[:at] + socksVersionMarker + strings.Join(parts, ",") + socksVersionNote + "\n" + body[at:]
}

// socksVersionsIn reads back the versions a stamped config carries:
// credential id → version (nil when it is not stamped or the line is not
// one this file writes).
func socksVersionsIn(body string) map[string]int {
	rest, ok := strings.CutPrefix(body, socksVersionMarker)
	if !ok {
		if _, rest, ok = strings.Cut(body, "\n"+socksVersionMarker); !ok {
			return nil
		}
	}
	rest, _, _ = strings.Cut(rest, "\n")
	rest, _, _ = strings.Cut(rest, " ")
	out := map[string]int{}
	for _, kv := range strings.Split(rest, ",") {
		id, vs, ok := strings.Cut(kv, "=")
		v, err := strconv.Atoi(vs)
		if !ok || err != nil || v <= 0 || !strings.HasPrefix(id, credentials.SOCKSIDPrefix+"-") || !credentials.ValidID(id) {
			return nil
		}
		out[id] = v
	}
	return out
}

// socksVersionsOf merges the versions the redirector configs among files
// carry (nil when none does).
func socksVersionsOf(files map[string]string) map[string]int {
	var out map[string]int
	for p, body := range files {
		if !isExtProxyConfig(p) {
			continue
		}
		for id, v := range socksVersionsIn(body) {
			if out == nil {
				out = map[string]int{}
			}
			out[id] = v
		}
	}
	return out
}

// socksCredsOf lists the SOCKS credential ids the redirector configs among
// files name (sorted, unique).
func socksCredsOf(files map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for p, body := range files {
		if !isExtProxyConfig(p) {
			continue
		}
		for _, id := range socksCredIDsIn(body) {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

// trackedSOCKS are the versions to compile in: those of the tracked
// credentials among vs.
func trackedSOCKS(vs map[string]credentials.SOCKSVersion) map[string]int {
	out := map[string]int{}
	for id, v := range vs {
		if v.Tracked {
			out[id] = v.Version
		}
	}
	return out
}

// stampSOCKS is the step of compileWith that writes the current version of
// each tracked SOCKS credential into the redirector configs that name it.
// b is returned as is when there is no such config, no tracked credential
// (among them: no baseline yet), or no credential store (the install,
// which needs the store, refuses then anyway).
func (s *Server) stampSOCKS(b *compile.Bundle) *compile.Bundle {
	if b == nil {
		return b
	}
	ids := socksCredsOf(b.Files)
	if len(ids) == 0 {
		return b
	}
	cs, err := s.credStore()
	if err != nil {
		return b
	}
	vers := trackedSOCKS(cs.SOCKSVersions(ids))
	if len(vers) == 0 {
		return b
	}
	nb := *b
	nb.Files = make(map[string]string, len(b.Files))
	for p, body := range b.Files {
		if isExtProxyConfig(p) {
			body = stampSOCKSVersions(body, vers)
		}
		nb.Files[p] = body
	}
	return &nb
}

// errSOCKSRotated: a SOCKS credential was rotated between the compilation
// of a carrier's files and the read of its secrets.
var errSOCKSRotated = errors.New("socks credential rotated")

// socksInstallSnapshot reads, in one snapshot of the credential store, the
// username and password of the SOCKS credentials ids (those the carrier's
// external exits name) and the version of each. The versions must be the
// ones files were compiled with — the line names exactly the tracked
// credentials, at these versions — or errSOCKSRotated is returned: files
// (and the preflight reviewed for their digest) are from before a
// rotation. applied is what an install of files with these secrets puts on
// the carrier: credential id → version, never a value.
func socksInstallSnapshot(cs *credentials.Store, ids []string, files map[string]string) (secrets map[string]string, applied map[string]int, err error) {
	secrets, vers, err := cs.SOCKSSecretsVersioned(ids)
	if err != nil {
		return nil, nil, err
	}
	if !sameVersions(trackedSOCKS(vers), socksVersionsOf(files)) {
		return nil, nil, errSOCKSRotated
	}
	applied = map[string]int{}
	for id, v := range vers {
		applied[id] = v.Version
	}
	return secrets, applied, nil
}

// socksState is what a node's row says about the SOCKS credentials its
// files name.
type socksState struct {
	// Planned: the versions compiled into the files (tracked credentials).
	Planned map[string]int
	// Installed: the versions the last successful install is known to have
	// applied.
	Installed map[string]int
	// Unrecorded: credentials the files name whose installed version is
	// not known (sorted).
	Unrecorded []string
}

// socksStateOf works out a carrier's socksState. inSync: the installed
// bundle is the current one, so the versions in the files are the
// installed ones; recorded: what the last successful install recorded.
func socksStateOf(files map[string]string, recorded map[string]int, inSync bool) socksState {
	st := socksState{Planned: socksVersionsOf(files)}
	ids := socksCredsOf(files)
	if len(ids) == 0 {
		return st
	}
	for _, id := range ids {
		v := recorded[id]
		if inSync && st.Planned[id] > 0 {
			// Part of the digest that matched.
			v = st.Planned[id]
		}
		if v <= 0 {
			st.Unrecorded = append(st.Unrecorded, id)
			continue
		}
		if st.Installed == nil {
			st.Installed = map[string]int{}
		}
		st.Installed[id] = v
	}
	return st
}

// socksUnrecordedNote is the note of a carrier that is in sync but whose
// install recorded no version for ids (it was installed before versions
// were tracked, and the credentials have not been rotated since).
func socksUnrecordedNote(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return "这个节点承载的外部 SOCKS 出口使用的凭据 " + strings.Join(ids, "、") + " 在面板开始记录凭据版本之前就已存在，这个节点安装时没有记录用的是哪一版：" +
		"面板不能证明节点上的用户名和密码就是现在保存的（升级之前轮换过而没有重新下发的话，节点上仍是旧的）。" +
		"升级本身不把它算作待下发；要确认，重新预检并安装一次（配置内容不变，只是重写同样的文件并记下版本）。此后每次轮换都会让它显示待下发"
}

// socksChangeReason explains a changed carrier whose files carry SOCKS
// credential versions (planned): rotated since its install (recorded: what
// that install applied), or rotated since the baseline while its install
// recorded nothing. "" when the versions are not the reason — among them
// a credential the carrier has never been installed with.
func socksChangeReason(planned, recorded map[string]int, info map[string]credentials.SOCKSVersion) string {
	ids := make([]string, 0, len(planned))
	for id := range planned {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var rotated, legacy []string
	for _, id := range ids {
		switch iv, ok := recorded[id]; {
		case ok && iv != planned[id]:
			rotated = append(rotated, fmt.Sprintf("%s 已安装版本 %d，现在是版本 %d", id, iv, planned[id]))
		case !ok && info[id].Baseline > 0:
			legacy = append(legacy, fmt.Sprintf("%s 现在是版本 %d", id, planned[id]))
		}
	}
	switch {
	case len(rotated) > 0:
		return "外部 SOCKS 凭据已轮换（" + strings.Join(append(rotated, legacy...), "；") + "）：" +
			"承载节点仍在用旧的用户名和密码，重新预检并安装后才用新的"
	case len(legacy) > 0:
		return "外部 SOCKS 凭据在面板开始记录版本之后轮换过（" + strings.Join(legacy, "；") + "；这个节点上次安装时还没有记录凭据版本）：" +
			"承载节点仍在用轮换之前的用户名和密码，重新预检并安装后才用新的"
	}
	return ""
}

// withSOCKSVersions folds the SOCKS credential versions b's files carry
// into a deployment plan version v (unchanged when they carry none), so a
// rotation makes an open run stale like a topology change.
func withSOCKSVersions(v string, b *compile.Bundle) string {
	if b == nil {
		return v
	}
	vers := socksVersionsOf(b.Files)
	if len(vers) == 0 {
		return v
	}
	h := sha256.Sum256([]byte(v + "\nsocks " + versionsText(vers)))
	return hex.EncodeToString(h[:])[:16]
}

// socksCarriers lists the managed nodes that carry an external exit using
// credential id (sorted): the nodes a rotation makes pending.
func socksCarriers(t model.Topology, id string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, n := range t.Nodes {
		if !model.IsExternal(n) || n.External.CredentialID != id || seen[n.External.Carrier] {
			continue
		}
		if c, ok := t.NodeByID(n.External.Carrier); ok && c.Managed {
			seen[c.ID] = true
			out = append(out, c.ID)
		}
	}
	sort.Strings(out)
	return out
}

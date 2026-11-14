package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ruleset"
)

// The whole-document save (PUT /api/topology) and the independent resources.
//
// Some blocks of the topology document have their own endpoints and are
// written only there: service groups, rule-sets, the mihomo import mapping,
// remote access and the sniff setting. The whole-document save never writes
// them. A request may
//
//   - omit the field (or send null): the stored value is kept;
//   - send a value equal to the stored one (an honest round trip of a
//     document just fetched): the stored value is kept;
//   - send anything else: the save is refused as a whole, nothing is
//     written, 409 independent_resource_changed with every offending field,
//     the entries that differ and the endpoint to use.
//
// A document fetched before another client changed one of these blocks
// through its own endpoint carries the old value: it differs from the
// stored one and is refused like an edit, because the two cannot be told
// apart and keeping the stored value would be exactly the silent drop this
// contract replaces. The refusal says so; reloading (or omitting the field)
// resolves it. The panel's own editors omit these fields (web/src/api.ts
// putTopology). docs/architecture.md「整份拓扑保存与独立资源」 has the
// table of every field.

// codeIndependentChanged is the refusal of a whole-document save that
// carries a changed independent resource (409).
const codeIndependentChanged = "independent_resource_changed"

// independentRefusal is one offending field of the refusal.
type independentRefusal struct {
	// Field is the document path ("service_groups", "settings.sniff").
	Field string `json:"field"`
	// Resource is what it is, in the panel's words.
	Resource string `json:"resource"`
	// Endpoint is the API that owns it; Methods its writing requests.
	Endpoint string   `json:"endpoint"`
	Methods  []string `json:"methods"`
	// Items are the entries that differ (IDs of added, removed or changed
	// list entries; "settings" for remote access's own settings), when the
	// field is a list. Empty for a single value.
	Items []string `json:"items,omitempty"`
}

// errIndependentChanged carries the refusal out of the store guard.
type errIndependentChanged struct{ fields []independentRefusal }

func (e *errIndependentChanged) Error() string {
	names := make([]string, 0, len(e.fields))
	for _, f := range e.fields {
		names = append(names, f.Resource+"（"+f.Field+"，用 "+f.Endpoint+"）")
	}
	return "整份拓扑保存不能修改独立资源：" + strings.Join(names, "、") +
		"。没有保存任何内容。如果你没有改它们，说明这份文档是在它们被各自的接口修改之前读取的：重新读取拓扑后再改，或在请求里省略这些字段。"
}

// independentField is one block owned by its own endpoint.
type independentField struct {
	field, resource, endpoint string
	methods                   []string
	// importWrites: ?import=1 (an export brought back) writes the block
	// wholesale, so it is not checked there.
	importWrites bool
	sent         func(p docPresence) bool
	// diff reports whether in carries another value than cur, and which
	// entries differ.
	diff func(in, cur model.Topology) (bool, []string)
	keep func(dst *model.Topology, cur model.Topology)
}

// docPresence records which independent fields a request body carries
// (key present and not null). encoding/json matches keys the same way as
// the decode into model.Topology does.
type docPresence struct {
	RuleSets      json.RawMessage `json:"rule_sets"`
	ServiceGroups json.RawMessage `json:"service_groups"`
	MihomoImport  json.RawMessage `json:"mihomo_import"`
	RemoteAccess  json.RawMessage `json:"remote_access"`
	Settings      struct {
		Sniff json.RawMessage `json:"sniff"`
	} `json:"settings"`
}

func sentRaw(r json.RawMessage) bool {
	t := bytes.TrimSpace(r)
	return len(t) > 0 && !bytes.Equal(t, []byte("null"))
}

// presenceOf reads which fields body carries. A body whose "settings" is
// not an object fails the decode into model.Topology first.
func presenceOf(body []byte) docPresence {
	var p docPresence
	_ = json.Unmarshal(body, &p)
	return p
}

func canonJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// diffByID compares two ID-keyed lists without regard to order (the order
// of these lists carries no meaning and the save never reorders them).
// norm maps an incoming entry to its comparable form given the stored one.
func diffByID[T any](in, cur []T, id func(T) string, norm func(in T, cur *T) T) (bool, []string) {
	stored := map[string]T{}
	for _, x := range cur {
		stored[id(x)] = x
	}
	seen := map[string]bool{}
	var items []string
	add := func(s string) {
		for _, x := range items {
			if x == s {
				return
			}
		}
		items = append(items, s)
	}
	for _, x := range in {
		k := id(x)
		if seen[k] {
			add(k) // a duplicate is never what is stored
			continue
		}
		seen[k] = true
		c, ok := stored[k]
		if !ok {
			add(k)
			continue
		}
		if norm != nil {
			x = norm(x, &c)
		}
		if canonJSON(x) != canonJSON(c) {
			add(k)
		}
	}
	for _, x := range cur {
		if !seen[id(x)] {
			add(id(x))
		}
	}
	sort.Strings(items)
	return len(items) > 0, items
}

// independentFields are the blocks the whole-document save never writes.
var independentFields = []independentField{
	{
		field: "service_groups", resource: "服务组", endpoint: "/api/service-groups",
		methods:      []string{"POST /api/service-groups", "PATCH /api/service-groups/{id}", "DELETE /api/service-groups/{id}"},
		importWrites: true,
		sent:         func(p docPresence) bool { return sentRaw(p.ServiceGroups) },
		diff: func(in, cur model.Topology) (bool, []string) {
			return diffByID(in.ServiceGroups, cur.ServiceGroups, func(g model.ServiceGroup) string { return g.ID }, nil)
		},
		keep: func(dst *model.Topology, cur model.Topology) { dst.ServiceGroups = cur.ServiceGroups },
	},
	{
		field: "rule_sets", resource: "规则集", endpoint: "/api/rule-sets",
		methods:      []string{"POST /api/rule-sets", "PATCH /api/rule-sets/{id}", "DELETE /api/rule-sets/{id}", "PUT /api/rule-sets/{id}/auth"},
		importWrites: true,
		sent:         func(p docPresence) bool { return sentRaw(p.RuleSets) },
		diff: func(in, cur model.Topology) (bool, []string) {
			// GET /api/topology shows a URL that still carries a credential
			// without it (store.Redact): that form is the stored URL.
			return diffByID(in.RuleSets, cur.RuleSets, func(r model.RuleSet) string { return r.ID }, func(x model.RuleSet, c *model.RuleSet) model.RuleSet {
				if x.URL != c.URL && ruleset.HasSecret(c.URL) && x.URL == ruleset.Redact(c.URL) {
					x.URL = c.URL
				}
				return x
			})
		},
		keep: func(dst *model.Topology, cur model.Topology) { dst.RuleSets = cur.RuleSets },
	},
	{
		field: "mihomo_import", resource: "mihomo 导入的映射记录", endpoint: "/api/rules/import/confirm",
		methods:      []string{"POST /api/rules/import/confirm"},
		importWrites: true,
		sent:         func(p docPresence) bool { return sentRaw(p.MihomoImport) },
		diff: func(in, cur model.Topology) (bool, []string) {
			// Absent and an empty record are the same (an empty mapping
			// is not serialised either).
			norm := func(m *model.MihomoImport) string {
				if m == nil {
					m = &model.MihomoImport{}
				}
				return canonJSON(m)
			}
			return norm(in.MihomoImport) != norm(cur.MihomoImport), nil
		},
		keep: func(dst *model.Topology, cur model.Topology) { dst.MihomoImport = cur.MihomoImport },
	},
	{
		field: "remote_access", resource: "远程接入", endpoint: "/api/remote-access",
		methods: []string{"PUT /api/remote-access", "POST /api/remote-access/devices", "PATCH /api/remote-access/devices/{id}",
			"DELETE /api/remote-access/devices/{id}", "POST /api/remote-access/devices/{id}/regenerate"},
		sent: func(p docPresence) bool { return sentRaw(p.RemoteAccess) },
		diff: func(in, cur model.Topology) (bool, []string) {
			split := func(r *model.RemoteAccess) (model.RemoteAccess, []model.RemoteDevice) {
				if r == nil {
					return model.RemoteAccess{}, nil
				}
				x := *r
				d := x.Devices
				x.Devices = nil
				return x, d
			}
			ia, id := split(in.RemoteAccess)
			ca, cd := split(cur.RemoteAccess)
			_, items := diffByID(id, cd, func(d model.RemoteDevice) string { return d.ID }, nil)
			if canonJSON(ia) != canonJSON(ca) {
				items = append([]string{"settings"}, items...)
			}
			return len(items) > 0, items
		},
		keep: func(dst *model.Topology, cur model.Topology) { dst.RemoteAccess = cur.RemoteAccess.Clone() },
	},
	{
		field: "settings.sniff", resource: "按域名嗅探的转发", endpoint: "/api/sniff",
		methods:      []string{"PUT /api/sniff"},
		importWrites: true,
		sent:         func(p docPresence) bool { return sentRaw(p.Settings.Sniff) },
		diff: func(in, cur model.Topology) (bool, []string) {
			// Absent and the zero setting (off, defaults) are the same.
			norm := func(s *model.SniffSettings) string {
				if s == nil {
					s = &model.SniffSettings{}
				}
				return canonJSON(s)
			}
			return norm(in.Settings.Sniff) != norm(cur.Settings.Sniff), nil
		},
		keep: func(dst *model.Topology, cur model.Topology) { dst.Settings.Sniff = cur.Settings.Sniff },
	},
}

// checkIndependent compares the independent fields the request sent with
// the stored document. It returns the refusals (none: the save may go on).
func checkIndependent(p docPresence, in, cur model.Topology, imported bool) []independentRefusal {
	var out []independentRefusal
	for _, f := range independentFields {
		if imported && f.importWrites || !f.sent(p) {
			continue
		}
		if differs, items := f.diff(in, cur); differs {
			out = append(out, independentRefusal{Field: f.field, Resource: f.resource, Endpoint: f.endpoint, Methods: f.methods, Items: items})
		}
	}
	return out
}

// keepIndependent puts the stored blocks into the document to be saved
// (every independent field, whatever was sent: after checkIndependent,
// what was sent is either absent or equal).
func keepIndependent(dst *model.Topology, cur model.Topology, imported bool) {
	for _, f := range independentFields {
		if imported && f.importWrites {
			continue
		}
		f.keep(dst, cur)
	}
}

// independentGuard is the store guard of a whole-document save: the same
// check and the same keep against the document stored at the moment of the
// write, so a change made through an independent endpoint after the
// handler's first check is neither overwritten nor silently accepted.
func independentGuard(p docPresence, sent model.Topology, imported bool) func(prev model.Topology, next *model.Topology) error {
	return func(prev model.Topology, next *model.Topology) error {
		if refused := checkIndependent(p, sent, prev, imported); len(refused) > 0 {
			return &errIndependentChanged{fields: refused}
		}
		keepIndependent(next, prev, imported)
		return nil
	}
}

func writeIndependentRefusal(w http.ResponseWriter, err error) bool {
	var e *errIndependentChanged
	if !errors.As(err, &e) {
		return false
	}
	writeJSON(w, http.StatusConflict, map[string]any{"error": e.Error(), "code": codeIndependentChanged, "fields": e.fields})
	return true
}

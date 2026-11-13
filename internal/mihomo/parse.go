// Package mihomo reads the rule part of a mihomo (Clash.Meta) config and
// turns it into the panel's ordered rule list with a preview (import.go).
//
// Only three top-level sections are read: rules, rule-providers and
// proxy-groups. Everything else — proxies (server addresses, passwords,
// UUIDs, private keys), proxy-providers (subscription URLs with tokens),
// dns, tun, the controller secret — is never decoded into anything kept:
// the YAML tree of other keys is dropped as soon as the document is parsed,
// nothing of it is stored, logged or returned. Parsing uses a real YAML
// parser (gopkg.in/yaml.v3): anchors, aliases, merge keys ("<<: *pr"),
// flow-style maps, quoted names and comments are YAML, not special cases.
package mihomo

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/radowitz/meridian/internal/ruleset"
)

// MaxConfigBytes bounds a pasted config.
const MaxConfigBytes = 4 << 20

// Provider is one rule-provider.
type Provider struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Behavior string `json:"behavior"`
	Format   string `json:"format,omitempty"`
	URL      string `json:"url,omitempty"`
	Interval int    `json:"interval,omitempty"`
	// Auth is the credential the URL carried (user information or secret
	// query parameters, ruleset.SplitSecret); URL is then the URL without
	// it. It goes to the credential store on confirm and is never shown.
	Auth *ruleset.Auth `json:"-"`
	// URLError: the URL carries a credential that cannot be split off.
	URLError string `json:"-"`
}

// Group is one proxy-group: only what the mapping needs.
type Group struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Proxies []string `json:"proxies,omitempty"`
	Use     []string `json:"use,omitempty"`
	Filter  string   `json:"filter,omitempty"`
}

// RawRule is one entry of the rules list with its source line.
type RawRule struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

// Config is the rule part of a mihomo config.
type Config struct {
	Rules      []RawRule
	Providers  map[string]Provider
	Groups     map[string]Group
	GroupOrder []string
}

// Parse reads rules, rule-providers and proxy-groups from a whole config or
// from just those sections.
func Parse(text string) (Config, error) {
	cfg := Config{Providers: map[string]Provider{}, Groups: map[string]Group{}}
	if len(text) > MaxConfigBytes {
		return cfg, fmt.Errorf("配置超过 %d MiB", MaxConfigBytes>>20)
	}
	text = strings.TrimPrefix(text, "\ufeff")
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		// The parser's message can quote the offending line, which may be
		// part of the proxies section: only its line number is returned.
		return cfg, errors.New("YAML 无法解析" + yamlErrLine(err))
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return cfg, errors.New("不是 YAML 映射：需要 rules、rule-providers、proxy-groups 段")
	}
	top := doc.Content[0]
	found := false
	for i := 0; i+1 < len(top.Content); i += 2 {
		k, v := top.Content[i].Value, top.Content[i+1]
		switch k {
		case "rules":
			found = true
			if v.Kind != yaml.SequenceNode {
				return cfg, errors.New("rules 不是列表")
			}
			for _, it := range v.Content {
				if it.Kind != yaml.ScalarNode {
					return cfg, fmt.Errorf("第 %d 行：rules 的条目不是字符串", it.Line)
				}
				cfg.Rules = append(cfg.Rules, RawRule{Line: it.Line, Text: strings.TrimSpace(it.Value)})
			}
		case "rule-providers":
			var m map[string]map[string]any
			if err := v.Decode(&m); err != nil {
				return cfg, errors.New("rule-providers 无法解析" + yamlErrLine(err))
			}
			for name, p := range m {
				pr := Provider{
					Name: name, Type: str(p["type"]), Behavior: str(p["behavior"]), Format: str(p["format"]),
					URL: str(p["url"]), Interval: num(p["interval"]),
				}
				if ruleset.HasSecret(pr.URL) {
					clean, a, err := ruleset.SplitSecret(pr.URL)
					if err != nil {
						pr.URL, pr.URLError = ruleset.Redact(pr.URL), err.Error()
					} else {
						pr.URL, pr.Auth = clean, a
					}
				}
				cfg.Providers[name] = pr
			}
		case "proxy-groups":
			var gs []map[string]any
			if err := v.Decode(&gs); err != nil {
				return cfg, errors.New("proxy-groups 无法解析" + yamlErrLine(err))
			}
			for _, g := range gs {
				gr := Group{Name: str(g["name"]), Type: strings.ToLower(str(g["type"])), Proxies: strs(g["proxies"]), Use: strs(g["use"]), Filter: str(g["filter"])}
				if gr.Name == "" {
					continue
				}
				if _, dup := cfg.Groups[gr.Name]; !dup {
					cfg.GroupOrder = append(cfg.GroupOrder, gr.Name)
				}
				cfg.Groups[gr.Name] = gr
			}
		}
	}
	if !found {
		return cfg, errors.New("没有 rules 段")
	}
	return cfg, nil
}

func yamlErrLine(err error) string {
	var te *yaml.TypeError
	msg := err.Error()
	if errors.As(err, &te) && len(te.Errors) > 0 {
		msg = te.Errors[0]
	}
	if i := strings.Index(msg, "line "); i >= 0 {
		j := i + 5
		for j < len(msg) && msg[j] >= '0' && msg[j] <= '9' {
			j++
		}
		return "（第 " + msg[i+5:j] + " 行附近）"
	}
	return ""
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int, int64, float64, bool:
		return fmt.Sprint(x)
	}
	return ""
}

func num(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return 0
}

func strs(v any) []string {
	l, _ := v.([]any)
	var out []string
	for _, x := range l {
		if s := str(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Rule is one parsed rule line.
type Rule struct {
	Line      int
	Text      string
	Type      string
	Payload   string
	Policy    string
	NoResolve bool
	// Options other than no-resolve.
	Options []string
}

// splitTop splits at commas outside parentheses.
func splitTop(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, c := range s {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// ParseRule splits one rule line.
func ParseRule(r RawRule) (Rule, error) {
	f := splitTop(r.Text)
	out := Rule{Line: r.Line, Text: r.Text, Type: strings.ToUpper(f[0])}
	switch {
	case out.Type == "MATCH" || out.Type == "FINAL":
		if len(f) < 2 {
			return out, errors.New("MATCH 没有策略")
		}
		out.Type, out.Policy = "MATCH", f[1]
		return out, nil
	case len(f) < 3:
		return out, errors.New("字段不足（需要 类型,值,策略）")
	case out.Type == "AND" || out.Type == "OR" || out.Type == "NOT":
		// Logical: TYPE,(…),(…),POLICY — the policy is the last field.
		out.Payload, out.Policy = strings.Join(f[1:len(f)-1], ","), f[len(f)-1]
		return out, nil
	}
	out.Payload, out.Policy = f[1], f[2]
	for _, o := range f[3:] {
		if strings.EqualFold(o, "no-resolve") {
			out.NoResolve = true
		} else if o != "" {
			out.Options = append(out.Options, o)
		}
	}
	return out, nil
}

// QUIC shapes: the two logical rules that disable QUIC for non-domestic
// traffic, compared without spaces and with the country/category in
// lower case.
var quicShapes = map[string]string{
	"and,(and,(dst-port,443),(network,udp)),(not,((geosite,cn)))": "geosite",
	"and,(and,(dst-port,443),(network,udp)),(not,((geoip,cn)))":   "geoip",
}

// QUICShape reports whether r is one of the two QUIC rules (with REJECT).
func QUICShape(r Rule) (string, bool) {
	if r.Type != "AND" || !strings.EqualFold(r.Policy, "REJECT") {
		return "", false
	}
	k := strings.ToLower(strings.ReplaceAll(r.Type+","+r.Payload, " ", ""))
	shape, ok := quicShapes[k]
	return shape, ok
}

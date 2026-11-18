package mihomo

import (
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/defaults"
)

// An AI rule whose policy group does not resolve to a region group gets the
// US region group as its first suggestion; a streaming rule does not.
func TestAIUnresolvedSuggestsUS(t *testing.T) {
	topo := defaults.Example()
	cfg, err := Parse(`proxies:
  - { name: "Node X", type: socks5, server: 198.51.100.9, port: 1080 }
proxy-groups:
  - { name: Mystery AI, type: select, proxies: ["Node X"] }
  - { name: Mystery Media, type: select, proxies: ["Node X"] }
rules:
  - GEOSITE,openai,Mystery AI
  - DOMAIN-SUFFIX,netflix.com,Mystery Media
  - MATCH,DIRECT
`)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := Build(topo, cfg, Options{}, content)
	byName := map[string]MappingRow{}
	for _, m := range p.Mapping {
		byName[m.Name] = m
	}
	ai := byName["Mystery AI"]
	if len(ai.Suggestions) == 0 || ai.Suggestions[0].Value != "group:us" {
		t.Fatalf("AI mapping suggestions %+v, want group:us first", ai.Suggestions)
	}
	for _, sg := range byName["Mystery Media"].Suggestions {
		if strings.HasPrefix(sg.Value, "group:us") {
			t.Fatalf("streaming mapping suggests US: %+v", byName["Mystery Media"].Suggestions)
		}
	}
}

func TestAIRowDetection(t *testing.T) {
	for _, c := range []struct {
		typ, val string
		want     bool
	}{
		{"GEOSITE", "openai", true}, {"DOMAIN-SUFFIX", "chatgpt.com", true}, {"RULE-SET", "AI", true},
		{"GEOSITE", "category-ai-!cn", true}, {"DOMAIN-KEYWORD", "claude", true},
		{"GEOSITE", "netflix", false}, {"DOMAIN-SUFFIX", "viu.com", false}, {"RULE-SET", "Domestic Special", false},
	} {
		if got := aiRow(Row{Type: c.typ, Value: c.val}); got != c.want {
			t.Errorf("%s,%s: %v", c.typ, c.val, got)
		}
	}
}

// The built-in AI rules of the default table target the US group.
func TestDefaultAIRulesTargetUS(t *testing.T) {
	for _, r := range defaults.DefaultRules() {
		if aiRow(Row{Type: "GEOSITE", Value: r.MatchValue}) || aiRow(Row{Type: "DOMAIN", Value: r.MatchValue}) {
			if r.TargetGroup != "us" {
				t.Errorf("%s targets %q, want us", r.ID, r.TargetGroup)
			}
		}
	}
	n := 0
	for _, r := range defaults.DefaultRules() {
		switch r.ID {
		case "auto-openai", "auto-anthropic", "auto-gemini", "auto-copilot", "auto-perplexity", "auto-grok":
			n++
			if r.TargetGroup != "us" {
				t.Errorf("%s targets %q", r.ID, r.TargetGroup)
			}
		}
	}
	if n != 6 {
		t.Fatalf("found %d built-in AI rules", n)
	}
}

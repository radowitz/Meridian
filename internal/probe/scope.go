package probe

import (
	"sort"
	"strings"

	"github.com/radowitz/meridian/internal/unlock"
)

// Probe scope: where a service is probed and which rules belong to it.
//
// A global service (coverage section international or ai) is probed on
// every exit. A regional service is probed only on exits of its regions:
// Adapter.Regions when declared, otherwise its coverage section (hk, tw,
// jp, sg, us). An exit's regions come from the region groups it belongs to
// (RegionGroup.Region, folded by unlock.NormRegion); an exit in several
// groups of different regions belongs to each of them. See
// docs/unlock-methods.md「按地区探测」.

// RegionGlobal is the scope code of global services.
const RegionGlobal = "global"

// Global reports whether the adapter is a global service.
func (a Adapter) Global() bool {
	return a.Section == SectionInternational || a.Section == SectionAI
}

// ProbeRegions are the exit regions a regional adapter is probed on
// (normalised); nil for a global one.
func (a Adapter) ProbeRegions() []string {
	if a.Global() {
		return nil
	}
	src := a.Regions
	if len(src) == 0 {
		src = []string{a.Section}
	}
	out := make([]string, 0, len(src))
	for _, r := range src {
		out = append(out, unlock.NormRegion(r))
	}
	return out
}

// ProbesOn reports whether the adapter is probed on an exit whose region
// groups carry exitRegions. A global adapter runs everywhere; a regional
// one never runs on an exit without one of its regions.
func (a Adapter) ProbesOn(exitRegions []string) bool {
	if a.Global() {
		return true
	}
	for _, r := range a.ProbeRegions() {
		for _, e := range exitRegions {
			if unlock.NormRegion(e) == r {
				return true
			}
		}
	}
	return false
}

// InScope reports whether a probe of scope ("global", a region code, or ""
// for everything) includes the adapter.
func (a Adapter) InScope(scope string) bool {
	switch scope {
	case "":
		return true
	case RegionGlobal:
		return a.Global()
	}
	if a.Global() {
		return false
	}
	for _, r := range a.ProbeRegions() {
		if r == unlock.NormRegion(scope) {
			return true
		}
	}
	return false
}

// extraDomains are well-known domains of a service beyond its probe hosts.
var extraDomains = map[string][]string{
	"auto-netflix":    {"nflxvideo.net", "nflxext.com", "nflximg.net", "nflxso.net"},
	"auto-disney":     {"disney-plus.net", "bamgrid.com", "dssott.com", "disneystreaming.com"},
	"youtube-premium": {"youtu.be", "googlevideo.com", "ytimg.com"},
	"auto-openai":     {"chatgpt.com", "oaistatic.com", "oaiusercontent.com"},
	"auto-anthropic":  {"anthropic.com", "claude.com"},
	"auto-grok":       {"grok.com", "x.ai"},
	"auto-copilot":    {"copilot.microsoft.com"},
}

// keywords match rule-set, geosite and keyword names
// token by token (lower case, split on anything not a letter or digit).
var keywords = map[string][]string{
	"auto-netflix": {"netflix"}, "auto-disney": {"disney", "disneyplus"}, "youtube-premium": {"youtube"},
	"primevideo": {"primevideo"}, "dazn": {"dazn"}, "tvbanywhere": {"tvbanywhere"}, "nbatv": {"nba"},
	"auto-openai": {"openai", "chatgpt"}, "auto-anthropic": {"claude", "anthropic"}, "auto-gemini": {"gemini"},
	"auto-copilot": {"copilot"}, "auto-perplexity": {"perplexity"}, "auto-grok": {"grok"}, "metaai": {"metaai"},
	"coze": {"coze"}, "auto-mytvsuper": {"mytvsuper"}, "auto-viu": {"viu"}, "auto-bahamut": {"bahamut"},
	"auto-kktv": {"kktv"}, "auto-linetv": {"linetv"}, "auto-hami": {"hami", "hamivideo"}, "myvideo": {"myvideo"},
	"4gtv": {"4gtv"}, "friday-video": {"friday"}, "auto-abema": {"abema", "abematv"},
	"dmm-tv": {"dmm"}, "dmm": {"dmm"}, "hulu-jp": {"hulujp", "hulujapan"}, "radiko": {"radiko"}, "fod": {"fod"},
	"unext": {"unext"}, "nhk-plus": {"nhk"}, "bglobal-sea": {"biliintl", "bilibilitv"},
	"peacock": {"peacock", "peacocktv"}, "plutotv": {"pluto", "plutotv"}, "fubotv": {"fubo", "fubotv"},
	"philo": {"philo"}, "sling": {"sling"}, "tubi": {"tubi", "tubitv"}, "acorntv": {"acorn", "acorntv"},
	"britbox": {"britbox"}, "amcplus": {"amcplus"},
}

// sharedDomains are registrable domains that carry many unrelated
// services; a probe host under one of them stands only for itself.
var sharedDomains = map[string]bool{"google.com": true, "microsoft.com": true, "hinet.net": true}

func registrable(host string) string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(host, ".")), ".")
	n := 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 {
		switch labels[len(labels)-2] {
		case "com", "net", "co", "ne", "or", "go", "org":
			n = 3
		}
	}
	if len(labels) <= n {
		return strings.Join(labels, ".")
	}
	d := strings.Join(labels[len(labels)-n:], ".")
	if sharedDomains[d] {
		return strings.Join(labels, ".")
	}
	return d
}

// Domains are the service's domains a rule is matched against: the
// registrable domains of its primary checks' hosts plus well-known extra
// domains. Reference checks (Check.Primary false) do not decide the verdict
// and their results are not stored, so their domains never pull a rule
// into adopt or impact (an ABEMA verdict must not rewrite Niconico rules).
func (a Adapter) Domains() []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	for _, c := range a.Checks {
		if !c.Primary {
			continue
		}
		for _, h := range c.Hosts {
			add(registrable(h))
		}
	}
	for _, d := range extraDomains[a.Service] {
		add(d)
	}
	sort.Strings(out)
	return out
}

// Keywords are the primary platform's name tokens (never a reference
// platform's) that a rule-set, geosite or keyword name must
// contain to belong to the service.
func (a Adapter) Keywords() []string { return keywords[a.Service] }

func tokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
}

// MatchesDomain: name is one of the service's domains or under one.
func (a Adapter) MatchesDomain(name string) bool {
	name = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "."))
	if name == "" {
		return false
	}
	for _, d := range a.Domains() {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// MatchesName: a token of label equals one of the service's keywords
// (joined neighbours count too, so "Disney Plus" matches "disneyplus").
func (a Adapter) MatchesName(label string) bool {
	kw := a.Keywords()
	if len(kw) == 0 {
		return false
	}
	ts := tokens(label)
	for i, t := range ts {
		cands := []string{t}
		if i+1 < len(ts) {
			cands = append(cands, t+ts[i+1])
		}
		for _, c := range cands {
			for _, k := range kw {
				if c == k {
					return true
				}
			}
		}
	}
	return false
}

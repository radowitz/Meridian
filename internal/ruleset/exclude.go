package ruleset

import (
	"fmt"
	"strings"

	"github.com/radowitz/meridian/internal/ordered"
)

// Exclusions of a rule-set (model.RuleSet.Exclude; the semantics are in
// internal/ordered/exclude.go). They are written the way the set's entries
// are written and go through the same parser: a classical line
// ("DOMAIN-SUFFIX,example.com", "DOMAIN,a.example.com",
// "DOMAIN-WILDCARD,*.example.com", "DOMAIN-KEYWORD,ads",
// "IP-CIDR,198.51.100.0/24") in any set, or a bare line in the set's own
// notation when the set is a domain or ipcidr list ("+.example.com",
// ".example.com", "example.com", "198.51.100.0/24"). A kind the set's
// format cannot contain, and anything the set's parser refuses or does not
// execute, is refused. They are stored in the classical form
// (ExclusionLine), which reads the same whatever the set's format is.

// ExclusionError is one refused exclusion line.
type ExclusionError struct {
	// Line is the 1-based position among the given lines.
	Line  int    `json:"line"`
	Text  string `json:"text"`
	Error string `json:"error"`
}

// formatKinds are the entry kinds a format can contain (nil: every kind).
func formatKinds(format string) map[ordered.Kind]bool {
	switch format {
	case FormatClashDomain, FormatClashTextDomain:
		return map[ordered.Kind]bool{ordered.Exact: true, ordered.Suffix: true, ordered.Sub: true}
	case FormatSurgeDomainSet:
		return map[ordered.Kind]bool{ordered.Exact: true, ordered.Suffix: true}
	case FormatClashIPCIDR, FormatClashTextIPCIDR:
		return map[ordered.Kind]bool{ordered.CIDR: true}
	}
	return nil
}

var kindWords = map[ordered.Kind]string{
	ordered.Exact: "完整域名", ordered.Suffix: "域名后缀", ordered.Sub: "子域名通配", ordered.Keyword: "关键词", ordered.CIDR: "地址段",
}

// ExclusionLine is the stored form of an exclusion.
func ExclusionLine(e ordered.Entry) string {
	switch e.Kind {
	case ordered.Exact:
		return "DOMAIN," + e.Value
	case ordered.Suffix:
		return "DOMAIN-SUFFIX," + e.Value
	case ordered.Sub:
		return "DOMAIN-WILDCARD,*." + e.Value
	case ordered.Keyword:
		return "DOMAIN-KEYWORD," + e.Value
	case ordered.CIDR:
		if e.Prefix.Addr().Is4() {
			return "IP-CIDR," + e.Prefix.String()
		}
		return "IP-CIDR6," + e.Prefix.String()
	}
	return ""
}

// parseExclusion parses one line with the set's grammar.
func parseExclusion(line, format string) (ordered.Entry, string) {
	p := Parsed{Counts: map[string]int{}}
	classical := ruleType(line) != ""
	switch {
	case classical:
		p.classical(line, true)
	case format == FormatClashDomain || format == FormatClashTextDomain:
		p.clashDomain(line)
	case format == FormatSurgeDomainSet:
		p.surgeDomain(line)
	case format == FormatClashIPCIDR || format == FormatClashTextIPCIDR:
		p.cidr(line)
	case format == FormatAuto:
		if _, ok := parseCIDR(line); ok {
			p.cidr(line)
			break
		}
		return ordered.Entry{}, "规则集的格式还不确定（没有指定，也还没有下载过）：请写成 DOMAIN-SUFFIX,example.com、DOMAIN,example.com、DOMAIN-KEYWORD,词 或 IP-CIDR,地址段 这样的行"
	default:
		return ordered.Entry{}, "这个规则集是 " + format + " 格式：请写成 DOMAIN-SUFFIX,example.com 这样带类型的行"
	}
	if len(p.Entries) != 1 {
		for t := range p.Unsupported {
			switch t {
			case unsupportedInvalidEntry:
				return ordered.Entry{}, "写法不对：规则集也不会接受这一行"
			case "wildcard-one-label":
				return ordered.Entry{}, "「*.」只匹配下一级名字，网关表达不了（规则集里的这种条目也不执行）"
			case "wildcard", "DOMAIN-WILDCARD":
				return ordered.Entry{}, "这种通配写法网关表达不了（规则集里的这种条目也不执行）"
			default:
				return ordered.Entry{}, t + " 类条目网关不执行，不能用作排除"
			}
		}
		return ordered.Entry{}, "写法不对"
	}
	e := p.Entries[0]
	if ks := formatKinds(format); ks != nil && !ks[e.Kind] {
		return ordered.Entry{}, fmt.Sprintf("这个规则集是 %s 格式，不会有%s条目", format, kindWords[e.Kind])
	}
	return e, ""
}

// ParseExclusions parses exclusion lines for a set of the given format (the
// explicit format, else the detected one, else "" when unknown). Blank and
// comment lines are skipped, repeats dropped; entries keep their order.
func ParseExclusions(lines []string, format string) ([]ordered.Entry, []ExclusionError) {
	var out []ordered.Entry
	var errs []ExclusionError
	seen := map[ordered.Entry]bool{}
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
			continue
		}
		e, msg := parseExclusion(l, format)
		if msg != "" {
			errs = append(errs, ExclusionError{Line: i + 1, Text: l, Error: msg})
			continue
		}
		if seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	if len(out) > ordered.MaxExclusions {
		errs = append(errs, ExclusionError{Line: len(lines), Error: fmt.Sprintf("排除条目最多 %d 条", ordered.MaxExclusions)})
	}
	return out, errs
}

// ExclusionEntries reads stored exclusions (ExclusionLine form). A line
// that does not read is skipped: validation refuses a topology with one.
func ExclusionEntries(lines []string) []ordered.Entry {
	es, _ := ParseExclusions(lines, FormatAuto)
	return es
}

// CheckStoredExclusions reports the stored exclusions of a set that are not
// in the stored form or that the set's format refuses.
func CheckStoredExclusions(lines []string, format string) []ExclusionError {
	_, errs := ParseExclusions(lines, format)
	if len(errs) > 0 {
		return errs
	}
	for i, l := range lines {
		e, msg := parseExclusion(strings.TrimSpace(l), FormatAuto)
		switch {
		case msg != "":
			errs = append(errs, ExclusionError{Line: i + 1, Text: l, Error: msg})
		case ExclusionLine(e) != l:
			errs = append(errs, ExclusionError{Line: i + 1, Text: l, Error: "不是保存格式（应为 " + ExclusionLine(e) + "）"})
		}
	}
	return errs
}

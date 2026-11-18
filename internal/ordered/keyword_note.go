package ordered

import "strconv"

// The one wording of what a keyword rule (or a rule-set's DOMAIN-KEYWORD
// entry) matches on the gateway. It depends on whether the name-sniffing
// forwarder is really in effect, not only on the saved switch; the API
// computes the state (internal/api/keyword_state.go) and every note the
// panel shows (rule list, new/edit drawer, rule-set preview, import
// analysis) takes its text from here. Display only.

// Keyword capability states.
const (
	// KeywordSniffOff: sniffing is off (or the state was not given).
	KeywordSniffOff = "off"
	// KeywordSniffOn: saved on, installed with the current settings and
	// running with usable paths.
	KeywordSniffOn = "on"
	// KeywordSniffPending: saved on, but not installed with the current
	// settings, not running, its paths failing or unchecked, or its state
	// unknown.
	KeywordSniffPending = "pending"
)

const (
	kwByName   = "TCP 接管端口上读得到名字的连接按子串匹配"
	kwRest     = "UDP（含 QUIC）、其它端口和读不到名字的连接"
	kwListOnly = "只匹配已下载名单里含这个词的域名（近似）"
)

// KeywordNote is the capability text of a keyword rule for the state; an
// unknown state reads as off (the most conservative claim).
func KeywordNote(state string) string {
	switch state {
	case KeywordSniffOn:
		return "嗅探已生效：" + kwByName + "；" + kwRest + "仍" + kwListOnly
	case KeywordSniffPending:
		return "嗅探安装并正常运行后，" + kwByName + "；现在仍" + kwListOnly
	}
	return "网关上只匹配已下载名单里含这个词的域名（SmartDNS 不能按子串匹配）"
}

// KeywordEntriesPrefix starts a KeywordEntriesNote.
func KeywordEntriesPrefix(n int) string { return strconv.Itoa(n) + " 条 DOMAIN-KEYWORD：" }

// KeywordEntriesNote is the rule-set note for n DOMAIN-KEYWORD entries
// (they have no list to approximate with: outside sniffing they do not
// execute). A stored note is recognised by its prefix and rewritten for
// the current state when shown.
func KeywordEntriesNote(n int, state string) string {
	return KeywordEntriesPrefix(n) + KeywordEntriesText(state)
}

// KeywordEntriesText is what KeywordEntriesNote says after its prefix.
func KeywordEntriesText(state string) string {
	switch state {
	case KeywordSniffOn:
		return "嗅探已生效：" + kwByName + "；" + kwRest + "不执行这些条目"
	case KeywordSniffPending:
		return "嗅探安装并正常运行后，" + kwByName + "；现在这些条目不执行"
	}
	return "SmartDNS 不能按子串匹配，这些条目不执行"
}

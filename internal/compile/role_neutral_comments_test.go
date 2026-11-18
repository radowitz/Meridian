package compile

import "strings"

// The failover scripts' header comments once named the relay's cloud
// provider; they are role-neutral now (docs/privacy-inventory.md). Pins
// that must not be regenerated (the stored pre-redesign topology, the
// no-Mesh compile, the review baseline) are compared with the old comment
// text put back, so they still prove every other byte is unchanged.
var legacyFailoverComments = strings.NewReplacer(
	"# Prefer UDP toward the relay. Fall back to WSS, then to the pre-provisioned gateway-to-hub WSS.\n",
	"# Prefer UDP toward Aliyun. Fall back to WSS, then to the pre-provisioned home-to-hub WSS.\n",
	"# Return path follows whichever west tunnel is actually up: IX, relay WSS, then gateway WSS.\n",
	"# Return path follows whichever west tunnel is actually up: IX, Aliyun WSS, then home WSS.\n",
)

// withLegacyFailoverComments returns a copy of b whose failover scripts
// carry the old comment text (only meridian-failover.sh is touched).
func withLegacyFailoverComments(b *Bundle) *Bundle {
	c := *b
	c.Files = make(map[string]string, len(b.Files))
	for p, body := range b.Files {
		if strings.HasSuffix(p, "/meridian-failover.sh") {
			body = legacyFailoverComments.Replace(body)
		}
		c.Files[p] = body
	}
	return &c
}

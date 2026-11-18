package compile

import (
	"strings"
	"testing"
)

// A return from an nft base chain executes its policy. The temporary fence
// must let management reach the existing firewall, while dropping everything
// else here. A drop policy silently defeats every management exception.
func TestShareFenceManagementReturnsReachExistingFirewall(t *testing.T) {
	start := strings.Index(shareTransactionShell, "  chain forward {")
	end := strings.Index(shareTransactionShell[start:], "\n  }")
	forward := shareTransactionShell[start : start+end]
	if !strings.Contains(forward, "policy accept;") {
		t.Fatal("management return in a base chain must reach an accepting policy")
	}
	for _, rule := range []string{
		"ip daddr 10.66.0.0/16 tcp dport 22 return",
		"ip6 daddr fd66::/48 tcp dport 22 return",
		"ip saddr 10.66.0.0/16 tcp sport 22 ct state established return",
		"ip6 saddr fd66::/48 tcp sport 22 ct state established return",
	} {
		if !strings.Contains(forward, rule) {
			t.Fatalf("missing tunnel management exception: %s", rule)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(forward), "counter drop") {
		t.Fatal("non-management forwarding must end at the fence drop")
	}
	// The gateway's own SSH over the tunnel, as client and as server (the
	// replies of its sshd), survives the fence; nothing else to 10.66/fd66.
	start = strings.Index(shareTransactionShell, "  chain output {")
	end = strings.Index(shareTransactionShell[start:], "\n  }")
	output := shareTransactionShell[start : start+end]
	for _, rule := range []string{
		"ip daddr 10.66.0.0/16 tcp dport 22 return",
		"ip6 daddr fd66::/48 tcp dport 22 return",
		"ip daddr 10.66.0.0/16 tcp sport 22 return",
		"ip6 daddr fd66::/48 tcp sport 22 return",
	} {
		i := strings.Index(output, rule)
		if i < 0 || i > strings.Index(output, "ip daddr 10.66.0.0/16 drop") {
			t.Fatalf("output management exception missing or after the drop: %s", rule)
		}
	}
}

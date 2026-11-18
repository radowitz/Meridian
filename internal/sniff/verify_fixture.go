package sniff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/radowitz/meridian/internal/ordered"
)

// VerifyFixture is the rule pair deploy/verify-sniff-systemd.sh starts a
// temporary forwarder with: no rule, everything to the direct target, one
// resolver on the loopback (the verification opens no connection through
// the forwarder; only the forwarder's own self-check asks it, at start, the
// fixed ". IN NS" question and one TCP handshake to it: selfcheck.go).
// Synthetic; nothing of a real topology.
func VerifyFixture() (snapshot, targets []byte) {
	const direct = 0x64
	snap := ordered.Snapshot{Version: ordered.SnapshotVersion, QUICAt: -1, Rules: []ordered.SnapshotRule{},
		Tail: ordered.SnapshotTail{DirectMark: direct, Default: "direct", DefaultMark: direct}}
	snapshot, err := json.MarshalIndent(snap, "", " ")
	if err != nil {
		panic(err) // plain structs: cannot fail
	}
	snapshot = append(snapshot, '\n')
	sum := sha256.Sum256(snapshot)
	m := uint32(direct)
	tf := TargetsFile{Version: TargetsVersion, SnapshotSHA256: hex.EncodeToString(sum[:]),
		Targets: []Target{{Name: "direct", Mark: direct, Resolvers: []string{"127.0.0.1:53"}, DNSMark: &m}}}
	targets, err = json.MarshalIndent(tf, "", " ")
	if err != nil {
		panic(err)
	}
	return snapshot, append(targets, '\n')
}

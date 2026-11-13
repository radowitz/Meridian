package compile

import (
	"net/netip"
	"testing"

	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/ordered"
)

// A keyword rule carries its keyword in decide.json, so a process that
// decides by the connection's name (internal/sniff) matches it as a
// substring, as mihomo does, and not only through the list expansion.
func TestDecideSnapshotKeyword(t *testing.T) {
	topo := orderedTopo([]model.Rule{rr("kw", model.MatchKeyword, "stream", "us")})
	b, err := Compile(topo)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ordered.LoadSnapshot([]byte(b.File("nodes/gw"+DecidePath)), ordered.MemReader{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := dec.Decide(ordered.Request{Name: "live-stream-1.example.net", Addr: netip.MustParseAddr("198.51.100.1")})
	if d.ID != "kw" || d.By != ordered.ByName {
		t.Fatalf("%+v", d)
	}
}

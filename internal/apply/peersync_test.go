package apply

import "testing"

func TestPeerOnlyDiff(t *testing.T) {
	mra, verify := PeerSyncFiles[0], PeerSyncFiles[1]
	for _, c := range []struct {
		d    ManifestDiff
		want bool
	}{
		{ManifestDiff{FilesChanged: []string{mra}}, true},
		{ManifestDiff{FilesChanged: []string{mra, verify}}, true},
		{ManifestDiff{FilesChanged: []string{verify}}, false},
		{ManifestDiff{FilesChanged: []string{mra, "etc/nftables.d/meridian.nft"}}, false},
		{ManifestDiff{FilesChanged: []string{mra}, UnitsAdded: []string{"meridian-x.service"}}, false},
		{ManifestDiff{FilesChanged: []string{mra}, FilesAdded: []string{"etc/wireguard/m01.conf"}}, false},
		{ManifestDiff{}, false},
	} {
		if got := PeerOnlyDiff(c.d); got != c.want {
			t.Errorf("%+v: %v", c.d, got)
		}
	}
	from := Manifest{Files: []ManagedFile{{Path: mra}}, Interfaces: []string{"mra"}}
	to := from
	to.Files = []ManagedFile{{Path: mra, SHA256: "x"}}
	if !PeerOnlyChange(from, to) {
		t.Error("peer change refused")
	}
	to.DNS = true
	if PeerOnlyChange(from, to) {
		t.Error("resolver change accepted")
	}
}

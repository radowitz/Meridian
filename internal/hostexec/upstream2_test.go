package hostexec

import (
	"strconv"
	"strings"
	"testing"
)

const rec2 = `meridian-upstream 2
beat 1700000100
path main
iface m02
hub ix
tier primary
since 1700000000
state ok
controller go
alert -
switched 0
designated access
relay access m02 active 500 0 - 1700000000 good 31000 4 30500 0 1700000100 1048576 2048 20480 100 12 - 0 - - - 0
relay access2 m03 evicted 0 1 no_throughput 1700000050 poor 120000 0 118000 0 1700000100 1024 2048 0 0 7 rtt_inflation 1700000060 420 862 0 640136
backup hkb m04 good 60000 0 60000 0 1700000100 0 0 0
end
`

func TestParseUpstreamV2(t *testing.T) {
	st, err := ParseUpstream(rec2)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != 2 || st.Path != "main" || st.Controller != "go" || st.Alert != "" || st.Designated != "access" || len(st.Relays) != 2 || st.Backup == nil {
		t.Fatalf("%+v", st)
	}
	r := st.Relays[1]
	if r.Status != "evicted" || !r.Drain || r.Reason != "no_throughput" || r.ProbeOK == nil || *r.ProbeOK || *r.ProbeKbps != 420 || r.ProbeBytesToday != 640136 || r.Suspicious != "rtt_inflation" {
		t.Fatalf("%+v", r)
	}
	if st.Relays[0].ProbeOK != nil || st.Relays[0].RTTus == nil || *st.Relays[0].RTTus != 31000 {
		t.Fatalf("%+v", st.Relays[0])
	}
	// v1 still parses.
	v1 := "meridian-upstream 1\nbeat 1700000100\npath udp\niface m00\nhub ix\ntier primary\nsince 1700000000\nstate ok\nend\n"
	if st, err := ParseUpstream(v1); err != nil || st.Version != 1 {
		t.Fatalf("v1: %v %+v", err, st)
	}
}

func TestParseUpstreamV2Strict(t *testing.T) {
	bad := map[string]string{
		"unknown state":    strings.Replace(rec2, "state ok", "state great", 1),
		"degraded is fine": "",
		"bad controller":   strings.Replace(rec2, "controller go", "controller panel", 1),
		"weight":           strings.Replace(rec2, "active 500", "active 2000", 1),
		"status":           strings.Replace(rec2, "active 500", "happy 500", 1),
		"extra field":      strings.Replace(rec2, "640136\n", "640136 x\n", 1),
		"missing field":    strings.Replace(rec2, " 640136\n", "\n", 1),
		"duplicate":        strings.Replace(rec2, "relay access2 m03", "relay access m03", 1),
		"no end":           strings.TrimSuffix(rec2, "end\n"),
		"unknown line":     strings.Replace(rec2, "end\n", "exec rm\nend\n", 1),
		"no relays":        strings.Join(strings.Split(rec2, "\n")[:12], "\n") + "\nend\n",
		"since after beat": strings.Replace(rec2, "since 1700000000", "since 1800000000", 1),
		"iface shell":      strings.Replace(rec2, "iface m02", "iface $(id)", 1),
		"alert shape":      strings.Replace(rec2, "alert -", "alert ALL-BAD", 1),
		"loss":             strings.Replace(rec2, "31000 4 30500", "31000 4000 30500", 1),
		"relay after bk":   strings.Replace(rec2, "end\n", "relay x m09 active 0 0 - 0 none - - - - 0 0 0 0 0 0 - 0 - - - 0\nend\n", 1),
		"too long":         rec2 + strings.Repeat("x", MaxUpstreamFile),
		"path":             strings.Replace(rec2, "path main", "path udp", 1),
	}
	for name, body := range bad {
		if body == "" {
			continue
		}
		if _, err := ParseUpstream(body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseUpstream(strings.Replace(rec2, "state ok", "state degraded", 1)); err != nil {
		t.Errorf("degraded: %v", err)
	}
}

func TestParseUpstreamV2BackupGroup(t *testing.T) {
	relay := func(id, iface string, w int) string {
		return "relay " + id + " " + iface + " active " + strconv.Itoa(w) + " 0 - 1700000000 good - - - - 0 0 0 0 0 0 - 0 - - - 0\n"
	}
	rec := "meridian-upstream 2\nbeat 1700000100\npath backup\niface m06\nhub hkb\ntier backup\nsince 1700000000\nstate ok\ncontroller go\nalert on_backup\nswitched 1700000000\ndesignated bk1\n" +
		relay("access", "m05", 0) + relay("bk1", "m06", 500) + relay("bk2", "m07", 500) + "backup_group hkb bk1 bk2\nend\n"
	st, err := ParseUpstream(rec)
	if err != nil || st.BackupGroup == nil || st.BackupGroup.Hub != "hkb" || st.Relays[0].Group != "main" || st.Relays[2].Group != "backup" {
		t.Fatalf("%v %+v", err, st)
	}
	for _, bad := range []string{
		strings.Replace(rec, "backup_group hkb bk1 bk2", "backup_group hkb access bk1 bk2", 1), // no main group
		strings.Replace(rec, "backup_group hkb bk1 bk2", "backup_group hkb bk1 bk1", 1),
		strings.Replace(rec, "backup_group hkb bk1 bk2", "backup_group hkb zz", 1),
	} {
		if _, err := ParseUpstream(bad); err == nil {
			t.Fatalf("accepted\n%s", bad)
		}
	}
}

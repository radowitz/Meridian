package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radowitz/meridian/internal/sniff"
)

func TestSniffDeviceNamesUseCurrentDHCPLeases(t *testing.T) {
	now := time.Unix(1000, 0)
	names := make(map[string]string)
	scanDHCPNames(strings.NewReader(`1200 aa 192.168.1.10 laptop *
900 bb 192.168.1.11 expired *
0 cc fd00::1 printer.local *
1200 dd 192.168.1.12 * *
1200 ee 192.168.1.13 bad/name *
1200 ff 192.168.1.14 unrelated *
`), map[string]struct{}{
		"192.168.1.10": {}, "192.168.1.11": {}, "fd00::1": {}, "192.168.1.12": {}, "192.168.1.13": {},
	}, names, now)
	if len(names) != 2 || names["192.168.1.10"] != "laptop" || names["fd00::1"] != "printer.local" {
		t.Fatalf("names = %v", names)
	}
}

func TestSniffDeviceNamesAreSeparateFromManualLabels(t *testing.T) {
	s, runtime := journalRig(t, false)
	file := filepath.Join(t.TempDir(), "dhcp.leases")
	if err := os.WriteFile(file, []byte(fmt.Sprintf("%d aa 192.168.1.10 laptop *\n", time.Now().Add(time.Hour).Unix())), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MERIDIAN_DHCP_LEASES_FILE", file)
	w := do(s, http.MethodGet, "/api/sniff/journal", nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "laptop") {
		t.Fatalf("unrelated hostname leaked into page: %d %s", w.Code, w.Body.String())
	}
	runtime.j.Add(sniff.ConnRecord{Start: time.Now(), Source: "192.168.1.10", Dest: "198.51.100.7:443", Result: "ok"})
	runtime.j.Flush()
	if w := do(s, http.MethodPut, "/api/sniff/devices/192.168.1.10/label", []byte(`{"label":"manual"}`)); w.Code != http.StatusOK {
		t.Fatalf("cannot set label: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/sniff/journal", "/api/sniff/devices"} {
		w := do(s, http.MethodGet, path, nil)
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, `"device_names":{"192.168.1.10":"laptop"}`) ||
			!strings.Contains(body, `"label":"manual"`) {
			t.Fatalf("%s: %d %s", path, w.Code, body)
		}
	}
}

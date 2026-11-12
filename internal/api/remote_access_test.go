package api

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type raResp struct {
	Settings struct {
		Enabled    bool     `json:"enabled"`
		Endpoint   string   `json:"endpoint"`
		ListenPort int      `json:"listen_port"`
		PublicKey  string   `json:"public_key"`
		DNS        []string `json:"dns"`
	} `json:"settings"`
	RouterForward struct {
		Protocol        string `json:"protocol"`
		ExternalPort    int    `json:"external_port"`
		InternalAddress string `json:"internal_address"`
	} `json:"router_forward"`
	Device  raDevice   `json:"device"`
	Devices []raDevice `json:"devices"`
	Config  *struct {
		Text        string `json:"text"`
		Filename    string `json:"filename"`
		Explanation string `json:"explanation"`
		ShownOnce   bool   `json:"shown_once"`
	} `json:"config"`
	ApplyRequired bool `json:"apply_required"`
}

type raDevice struct {
	ID              string `json:"id"`
	PublicKey       string `json:"public_key"`
	IPv4            string `json:"ipv4"`
	Enabled         bool   `json:"enabled"`
	PresharedKey    bool   `json:"preshared_key"`
	ConfigAvailable bool   `json:"config_available"`
	ConfigOutdated  bool   `json:"config_outdated"`
}

var (
	cfgPrivate = regexp.MustCompile(`(?m)^PrivateKey = (\S+)$`)
	cfgPSK     = regexp.MustCompile(`(?m)^PresharedKey = (\S+)$`)
)

func raCall(t *testing.T, s *Server, method, path, body string, want int) raResp {
	t.Helper()
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	rr := do(s, method, path, b)
	if rr.Code != want {
		t.Fatalf("%s %s: %d %s", method, path, rr.Code, rr.Body.String())
	}
	var out raResp
	if rr.Code < 300 {
		decode(t, rr, &out)
	}
	return out
}

func raErr(t *testing.T, s *Server, method, path, body, code, field string) {
	t.Helper()
	rr := do(s, method, path, []byte(body))
	var e apiErr
	decode(t, rr, &e)
	if e.Code != code || (field != "" && e.Field != field) || rr.Code < 400 {
		t.Fatalf("%s %s %s: want %s/%s, got %d %s", method, path, body, code, field, rr.Code, rr.Body.String())
	}
}

// The whole device lifecycle through the API, with the one-time
// configuration contract and secret isolation checked at every step.
func TestRemoteAccessLifecycleAndSecrets(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s, host, _ := installTest(t)

	if r := raCall(t, s, http.MethodGet, "/api/remote-access", "", 200); r.Settings.Enabled || len(r.Devices) != 0 {
		t.Fatalf("%+v", r)
	}
	raErr(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"phone"}`, codeRemoteNotConfigured, "endpoint")
	raErr(t, s, http.MethodPut, "/api/remote-access", `{"enabled":true}`, codeRemoteNotConfigured, "endpoint")
	raErr(t, s, http.MethodPut, "/api/remote-access", `{"endpoint":"home.example.net","listen_port":53}`, "remote_port_conflict", "listen_port")
	raErr(t, s, http.MethodPut, "/api/remote-access", `{"endpoint":"home.example.net","listen_port":51900,"ipv4_prefix":"192.168.100.0/25"}`, "remote_prefix_conflict", "ipv4_prefix")
	set := raCall(t, s, http.MethodPut, "/api/remote-access", `{"enabled":true,"endpoint":"home.example.net","listen_port":51900}`, 200)
	if !set.ApplyRequired || set.Settings.PublicKey == "" || set.RouterForward.ExternalPort != 51900 || set.RouterForward.Protocol != "udp" ||
		set.RouterForward.InternalAddress != "192.168.100.88" || strings.Join(set.Settings.DNS, ",") != "10.67.0.1,fd67::1" {
		t.Fatalf("%+v", set)
	}

	phone := raCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"phone"}`, 201)
	laptop := raCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"laptop","mode":"home","preshared_key":false}`, 201)
	if phone.Config == nil || !phone.Config.ShownOnce || phone.Device.ConfigAvailable || !phone.Device.PresharedKey || laptop.Device.PresharedKey {
		t.Fatalf("%+v %+v", phone, laptop)
	}
	if phone.Device.IPv4 != "10.67.0.2" || laptop.Device.IPv4 != "10.67.0.3" {
		t.Fatalf("addresses %s %s", phone.Device.IPv4, laptop.Device.IPv4)
	}
	priv := cfgPrivate.FindStringSubmatch(phone.Config.Text)
	psk := cfgPSK.FindStringSubmatch(phone.Config.Text)
	lpriv := cfgPrivate.FindStringSubmatch(laptop.Config.Text)
	if priv == nil || psk == nil || lpriv == nil || cfgPSK.MatchString(laptop.Config.Text) {
		t.Fatalf("configs:\n%s\n%s", phone.Config.Text, laptop.Config.Text)
	}
	cs, err := s.credStore()
	if err != nil {
		t.Fatal(err)
	}
	topo, _ := s.topology()
	gwKey, err := cs.WGSecret(topo.RemoteAccess.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{priv[1], psk[1], lpriv[1], gwKey}
	leak := func(where, text string) {
		t.Helper()
		for _, v := range secrets {
			if strings.Contains(text, v) {
				t.Fatalf("secret in %s", where)
			}
		}
	}
	// Nothing after the one-time response returns a secret.
	for _, p := range []string{"/api/remote-access", "/api/remote-access/devices", "/api/remote-access/devices/" + phone.Device.ID, "/api/topology"} {
		leak("GET "+p, do(s, http.MethodGet, p, nil).Body.String())
	}
	for _, p := range []string{"/api/compile", "/api/diff", "/api/validate"} {
		leak("POST "+p, do(s, http.MethodPost, p, []byte(`{}`)).Body.String())
	}
	raw, _, _ := s.Store.Get("topology")
	leak("stored topology", raw)

	// The topology editor cannot overwrite remote access.
	doc := do(s, http.MethodGet, "/api/topology", nil).Body.String()
	doc = strings.Replace(doc, `"remote_access":`, `"remote_access_ignored":`, 1)
	if rr := do(s, http.MethodPut, "/api/topology", []byte(doc)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	if r := raCall(t, s, http.MethodGet, "/api/remote-access", "", 200); len(r.Devices) != 2 || !r.Settings.Enabled {
		t.Fatal("PUT /api/topology dropped remote access")
	}

	// Install: the host config carries the PSK and the gateway key; the
	// response, snapshots and installed copy do not.
	rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	leak("apply response", rr.Body.String())
	mra, err := os.ReadFile(filepath.Join(host, "etc", "wireguard", "mra.conf"))
	if err != nil || !strings.Contains(string(mra), psk[1]) || !strings.Contains(string(mra), gwKey) {
		t.Fatalf("host mra.conf not injected: %v", err)
	}
	if strings.Contains(string(mra), priv[1]) || strings.Contains(string(mra), lpriv[1]) {
		t.Fatal("a device private key reached the gateway")
	}
	for _, v := range secrets {
		assertNowhereElse(t, s.DataDir, s.secretsDir(), v)
	}
	assertNowhereElse(t, host, filepath.Join(host, "etc", "wireguard"), priv[1])

	// Disable the laptop: its peer leaves the installed config.
	if r := raCall(t, s, http.MethodPatch, "/api/remote-access/devices/"+laptop.Device.ID, `{"enabled":false}`, 200); r.Device.Enabled || r.Config != nil {
		t.Fatalf("%+v", r)
	}
	if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	mra, _ = os.ReadFile(filepath.Join(host, "etc", "wireguard", "mra.conf"))
	if strings.Contains(string(mra), laptop.Device.PublicKey) || !strings.Contains(string(mra), phone.Device.PublicKey) {
		t.Fatal("disabled device still in the installed peer set")
	}

	// Regenerate: a new key pair and PSK, shown once; the old key is gone
	// from the topology.
	re := raCall(t, s, http.MethodPost, "/api/remote-access/devices/"+phone.Device.ID+"/regenerate", "", 200)
	npriv := cfgPrivate.FindStringSubmatch(re.Config.Text)
	npsk := cfgPSK.FindStringSubmatch(re.Config.Text)
	if npriv == nil || npsk == nil || npriv[1] == priv[1] || npsk[1] == psk[1] || re.Device.PublicKey == phone.Device.PublicKey || re.Device.IPv4 != phone.Device.IPv4 {
		t.Fatalf("regenerate: %+v", re.Device)
	}
	secrets = append(secrets, npriv[1], npsk[1])
	leak("GET after regenerate", do(s, http.MethodGet, "/api/remote-access", nil).Body.String())

	// Settings that the configs embed mark them outdated.
	raCall(t, s, http.MethodPut, "/api/remote-access", `{"listen_port":51901}`, 200)
	if d := raCall(t, s, http.MethodGet, "/api/remote-access/devices/"+phone.Device.ID, "", 200).Device; !d.ConfigOutdated {
		t.Fatal("port change must mark the delivered config outdated")
	}
	// Pools cannot change under existing devices.
	raErr(t, s, http.MethodPut, "/api/remote-access", `{"ipv4_prefix":"10.68.0.0/24"}`, "in_use", "ipv4_prefix")

	// A failed install is compensated and its error carries no secret.
	failed := false
	s.Activate = func() error {
		if failed {
			return nil
		}
		failed = true
		return errors.New("activation failed " + npsk[1])
	}
	rr = do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`))
	if rr.Code == 200 {
		t.Fatal("activation failure reported as success")
	}
	leak("failed apply", rr.Body.String())
	s.Activate = func() error { return nil }

	// Delete: 404 afterwards; the deleted device's PSK stays only while a
	// stored configuration still names it.
	raCall(t, s, http.MethodDelete, "/api/remote-access/devices/"+laptop.Device.ID, "", 200)
	raErr(t, s, http.MethodGet, "/api/remote-access/devices/"+laptop.Device.ID, "", "not_found", "")
	for i := 0; i < 2; i++ {
		if rr := do(s, http.MethodPost, "/api/apply", []byte(`{"install":true}`)); rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
	}
	topo, _ = s.topology()
	want := map[string]bool{topo.RemoteAccess.KeyID: true, topo.RemoteAccess.Devices[0].PSKID: true}
	for _, m := range cs.WGSecretIDs() {
		if !want[m.ID] {
			t.Errorf("unreferenced secret %s kept after two installs", m.ID)
		}
	}
	leak("logs", logs.String())
}

func TestRemoteAccessDeviceErrors(t *testing.T) {
	s := newTest(t)
	raCall(t, s, http.MethodPut, "/api/remote-access", `{"enabled":true,"endpoint":"home.example.net","listen_port":51900}`, 200)
	raErr(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":""}`, "invalid_field", "name")
	raErr(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"x","mode":"split"}`, "invalid_field", "mode")
	raErr(t, s, http.MethodPost, "/api/remote-access/devices", `not json`, "bad_request", "")
	raErr(t, s, http.MethodPatch, "/api/remote-access/devices/dev-nope", `{"name":"y"}`, "not_found", "")
	d := raCall(t, s, http.MethodPost, "/api/remote-access/devices", `{"name":"x"}`, 201)
	raErr(t, s, http.MethodPatch, "/api/remote-access/devices/"+d.Device.ID, `{"preshared_key":true}`, "invalid_field", "preshared_key")
}

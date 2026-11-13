package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/radowitz/meridian/internal/preflight"
)

// The embedded lock pins the three binaries for both architectures, with
// one version per binary, and only GitHub release URLs.
func TestEmbeddedLock(t *testing.T) {
	ps := Pins()
	if len(ps) != 6 {
		t.Fatalf("pins %+v", ps)
	}
	for _, name := range []string{Wstunnel, SmartDNS, Gost} {
		for _, arch := range []string{ArchAMD64, ArchARM64} {
			p, ok := PinFor(name, arch)
			if !ok || p.Version != Version(name) || !ValidSHA256(p.SHA256) || p.Size <= 0 || !strings.HasPrefix(p.URL, "https://github.com/") {
				t.Fatalf("%s/%s: %+v", name, arch, p)
			}
		}
	}
	if Version(Wstunnel) != "11.1.0" || Version(SmartDNS) != "1.2026.08.05-0921" || Version(Gost) != "3.2.6" {
		t.Fatalf("versions %s %s %s", Version(Wstunnel), Version(SmartDNS), Version(Gost))
	}
	a, _ := PinFor(Wstunnel, ArchAMD64)
	b, _ := PinFor(Wstunnel, ArchARM64)
	if a.SHA256 == b.SHA256 || a.URL == b.URL || !strings.Contains(a.URL, "linux_amd64") || !strings.Contains(b.URL, "linux_arm64") {
		t.Fatal("per-architecture pins must differ")
	}
	// The host paths are the ones the preflight asks about.
	for _, n := range preflight.ArtifactNames {
		if HostPath(n) != preflight.ArtifactPath(n) || !ValidName(n) {
			t.Fatalf("host path of %s differs between packages", n)
		}
	}
	if UnameArch("amd64") != ArchAMD64 || UnameArch("arm64") != ArchARM64 || UnameArch("riscv64") != "" {
		t.Fatal("uname mapping")
	}
}

func TestParseLockRefusesBadLines(t *testing.T) {
	good := "wstunnel 1.0 x86_64 " + strings.Repeat("a", 64) + " 10 " + strings.Repeat("b", 64) + " tar.gz wstunnel https://github.com/o/r/releases/download/v1/w.tar.gz\n"
	if _, err := ParseLock(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"",
		strings.Replace(good, "wstunnel 1.0", "curl 1.0", 1),
		strings.Replace(good, "x86_64", "armv7l", 1),
		strings.Replace(good, strings.Repeat("a", 64), "abc", 1),
		strings.Replace(good, " 10 ", " 0 ", 1),
		strings.Replace(good, " 10 ", " 99999999999 ", 1),
		strings.Replace(good, "tar.gz wstunnel", "zip wstunnel", 1),
		strings.Replace(good, "tar.gz wstunnel", "tar.gz ../x", 1),
		strings.Replace(good, "https://github.com/o/r/releases/download/v1/w.tar.gz", "http://example.net/w.tar.gz", 1),
		strings.Replace(good, "tar.gz wstunnel", "raw -", 1), // raw needs equal digests
		good + good,
		good + strings.Replace(good, "1.0 x86_64", "2.0 aarch64", 1),
	} {
		if _, err := ParseLock(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// fakePins returns pins for fake bytes and writes them to dir.
func fakePins(t *testing.T, dir string) ([]Pin, map[string][]byte) {
	t.Helper()
	var ps []Pin
	data := map[string][]byte{}
	for _, p := range Pins() {
		b := []byte("fake " + p.Name + " " + p.Arch + "\n")
		fp := Pin{Name: p.Name, Version: p.Version, Arch: p.Arch, SHA256: SHA256Of(b), Size: int64(len(b)), SourceKind: "raw", URL: p.URL}
		if err := os.WriteFile(filepath.Join(dir, fp.File()), b, 0o644); err != nil {
			t.Fatal(err)
		}
		ps = append(ps, fp)
		data[fp.File()] = b
	}
	return ps, data
}

// Load verifies every file (missing, wrong size, wrong digest, manifest
// disagreement are each refused per binary); Read verifies again at use.
func TestLoadAndRead(t *testing.T) {
	dir := t.TempDir()
	ps, data := fakePins(t, dir)
	b := LoadPins(dir, ps)
	for _, st := range b.Statuses() {
		if !st.Available {
			t.Fatalf("%s/%s: %s", st.Name, st.Arch, st.Error)
		}
	}
	got, pin, err := b.Read(SmartDNS, ArchARM64)
	if err != nil || string(got) != string(data["smartdns-aarch64"]) || pin.Arch != ArchARM64 {
		t.Fatalf("read %v %q", err, got)
	}
	// Per-architecture selection: the x86_64 copy differs.
	x, _, _ := b.Read(SmartDNS, ArchAMD64)
	if string(x) == string(got) {
		t.Fatal("architectures share bytes")
	}
	// Unknown architecture: unavailable with the reason.
	if st := b.Status(Wstunnel, "armv7l"); st.Available || !strings.Contains(st.Error, "armv7l") {
		t.Fatalf("armv7l %+v", st)
	}
	// A file changed after Load: refused at use and unavailable from then on.
	for _, p := range ps {
		if p.Name == Wstunnel && p.Arch == ArchAMD64 {
			os.WriteFile(filepath.Join(dir, p.File()), bytes.Repeat([]byte("x"), int(p.Size)), 0o644)
		}
	}
	if _, _, err := b.Read(Wstunnel, ArchAMD64); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered read: %v", err)
	}
	if b.Status(Wstunnel, ArchAMD64).Available {
		t.Fatal("tampered binary still available")
	}

	// Load-time failures.
	dir2 := t.TempDir()
	ps2, _ := fakePins(t, dir2)
	os.Remove(filepath.Join(dir2, "smartdns-x86_64"))
	os.WriteFile(filepath.Join(dir2, "smartdns-aarch64"), []byte("short"), 0o644)
	b2 := LoadPins(dir2, ps2)
	if st := b2.Status(SmartDNS, ArchAMD64); st.Available || !strings.Contains(st.Error, "不存在") {
		t.Fatalf("missing %+v", st)
	}
	if st := b2.Status(SmartDNS, ArchARM64); st.Available || !strings.Contains(st.Error, "大小") {
		t.Fatalf("size %+v", st)
	}
	if st := b2.Status(Wstunnel, ArchAMD64); !st.Available {
		t.Fatalf("intact file refused: %+v", st)
	}

	// manifest.txt: agreeing entries are fine, a disagreeing one refuses
	// that binary, a missing entry too.
	dir3 := t.TempDir()
	ps3, _ := fakePins(t, dir3)
	os.WriteFile(filepath.Join(dir3, ManifestFile), []byte(ManifestText(ps3)), 0o644)
	if b3 := LoadPins(dir3, ps3); !b3.Status(Wstunnel, ArchARM64).Available {
		t.Fatalf("agreeing manifest refused: %+v", b3.Status(Wstunnel, ArchARM64))
	}
	other := append([]Pin(nil), ps3...)
	for i := range other {
		if other[i].Name == Wstunnel && other[i].Arch == ArchARM64 {
			other[i].Version = "9.9.9"
		}
	}
	os.WriteFile(filepath.Join(dir3, ManifestFile), []byte(ManifestText(other[1:])), 0o644)
	b3 := LoadPins(dir3, ps3)
	if st := b3.Status(Wstunnel, ArchARM64); st.Available || !strings.Contains(st.Error, "manifest.txt") {
		t.Fatalf("manifest disagreement %+v", st)
	}
	if st := b3.Status(ps3[0].Name, ps3[0].Arch); st.Available {
		t.Fatalf("manifest without the entry %+v", st)
	}

	// No directory at all (and a nil bundle): everything unavailable.
	if st := Load(filepath.Join(t.TempDir(), "none")).Status(Wstunnel, ArchAMD64); st.Available {
		t.Fatal("missing directory")
	}
	var nb *Bundle
	if _, _, err := nb.Read(SmartDNS, ArchAMD64); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil bundle")
	}
}

// deploy/fetch-artifacts.sh (the image build step) with local copies only:
// a matching archive and binary pass, any digest mismatch fails the build.
// curl is replaced by a stub that fails, so nothing is downloaded.
func TestFetchScriptVerifiesWithoutDownloading(t *testing.T) {
	for _, tool := range []string{"sh", "tar", "cut", "wc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("no " + tool)
		}
	}
	script, err := filepath.Abs("../../deploy/fetch-artifacts.sh")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "curl"), []byte("#!/bin/sh\necho 'no downloads in tests' >&2\nexit 7\n"), 0o755)
	if p, err := exec.LookPath("sha256sum"); err == nil {
		os.Symlink(p, filepath.Join(bin, "sha256sum"))
	} else {
		os.WriteFile(filepath.Join(bin, "sha256sum"), []byte("#!/bin/sh\nexec shasum -a 256 \"$@\"\n"), 0o755)
	}
	local := t.TempDir()
	wsBin := []byte("fake wstunnel\n")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "wstunnel", Mode: 0o755, Size: int64(len(wsBin))})
	tw.Write(wsBin)
	tw.Close()
	zw.Close()
	os.WriteFile(filepath.Join(local, "w_linux_amd64.tar.gz"), gz.Bytes(), 0o644)
	sdBin := []byte("fake smartdns\n")
	os.WriteFile(filepath.Join(local, "smartdns-aarch64"), sdBin, 0o644)
	lock := func(wsArchive string) string {
		return "# test lock\n" +
			"wstunnel 1.0 x86_64 " + SHA256Of(wsBin) + " " + itoa(len(wsBin)) + " " + wsArchive + " tar.gz wstunnel https://github.com/o/r/releases/download/v1/w_linux_amd64.tar.gz\n" +
			"smartdns 2.0 aarch64 " + SHA256Of(sdBin) + " " + itoa(len(sdBin)) + " " + SHA256Of(sdBin) + " raw - https://github.com/o/s/releases/download/R1/smartdns-aarch64\n"
	}
	run := func(lockText string) (string, string, error) {
		dir := t.TempDir()
		lp := filepath.Join(dir, "artifacts.lock")
		os.WriteFile(lp, []byte(lockText), 0o644)
		out := filepath.Join(dir, "out")
		cmd := exec.Command("sh", script, lp, local, out)
		cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin"}
		b, err := cmd.CombinedOutput()
		return string(b), out, err
	}
	good := lock(SHA256Of(gz.Bytes()))
	if _, err := ParseLock(good); err != nil {
		t.Fatal(err)
	}
	outText, out, err := run(good)
	if err != nil {
		t.Fatalf("fetch: %v\n%s", err, outText)
	}
	ps, _ := ParseLock(good)
	b := LoadPins(out, ps)
	for _, st := range b.Statuses() {
		if !st.Available {
			t.Fatalf("built directory not accepted: %+v\n%s", st, outText)
		}
	}
	if strings.Contains(outText, "no downloads") {
		t.Fatal("the script tried to download")
	}
	// Archive digest mismatch fails the build.
	if outText, _, err := run(lock(strings.Repeat("0", 64))); err == nil || !strings.Contains(outText, "refusing") {
		t.Fatalf("archive mismatch accepted:\n%s", outText)
	}
	// Binary digest mismatch fails the build.
	bad := strings.Replace(good, SHA256Of(wsBin), strings.Repeat("1", 64), 1)
	if outText, _, err := run(bad); err == nil || !strings.Contains(outText, "refusing") {
		t.Fatalf("binary mismatch accepted:\n%s", outText)
	}
	// No local copy: it would download; with the failing stub the build fails.
	os.Remove(filepath.Join(local, "smartdns-aarch64"))
	if outText, _, err := run(good); err == nil || !strings.Contains(outText, "no downloads") {
		t.Fatalf("missing local copy:\n%s", outText)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// The image build fetches with the lock this package embeds.
func TestDockerfileUsesTheLock(t *testing.T) {
	df, err := os.ReadFile("../../deploy/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"COPY internal/artifacts/artifacts.lock", "fetch-artifacts.sh", "COPY deploy/artifacts/", "/usr/share/meridian/artifacts", "MERIDIAN_ARTIFACTS_DIR=" + DefaultDir} {
		if !strings.Contains(string(df), want) {
			t.Fatalf("Dockerfile lacks %q", want)
		}
	}
}

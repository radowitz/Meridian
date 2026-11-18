package probe

import (
	"context"
	"os"
	"testing"

	"github.com/radowitz/meridian/internal/unlock"
)

// prodCatalog is the registered catalog. The classifier and prober tests of
// this package still exercise the disabled AI adapters' code, so they run
// against every adapter written; the tests below check the registered set.
var prodCatalog = Catalog

func TestMain(m *testing.M) {
	Catalog = allAdapters
	os.Exit(m.Run())
}

func withProdCatalog(t *testing.T) {
	t.Helper()
	Catalog = prodCatalog
	t.Cleanup(func() { Catalog = allAdapters })
}

func TestAIAdaptersNotRegistered(t *testing.T) {
	withProdCatalog(t)
	ai := []string{"auto-openai", "auto-anthropic", "auto-gemini", "auto-copilot", "auto-perplexity", "auto-grok", "metaai", "coze"}
	for _, id := range ai {
		if _, ok := Lookup(id); ok || Probeable(id) || AutoRouteEligible(id) {
			t.Errorf("%s still registered", id)
		}
		if !IsAI(id) {
			t.Errorf("%s not marked disabled", id)
		}
	}
	for _, a := range Catalog {
		if a.Section == SectionAI {
			t.Errorf("AI adapter in catalog: %s", a.Service)
		}
	}
	for _, s := range Sections {
		if s == SectionAI {
			t.Fatal("AI section listed")
		}
	}
	for _, it := range Coverage {
		if it.Section == SectionAI {
			t.Fatalf("AI coverage item %s", it.Name)
		}
	}
	for _, id := range []string{"auto-netflix", "auto-disney", "youtube-premium", "primevideo", "dazn", "auto-mytvsuper", "auto-viu"} {
		if !Probeable(id) || IsAI(id) {
			t.Errorf("streaming service %s missing", id)
		}
	}
	// Global section is international streaming only.
	for _, a := range Catalog {
		if a.Global() && a.Section != SectionInternational {
			t.Errorf("%s global but section %s", a.Service, a.Section)
		}
	}
}

// The prober never sends a request for a disabled AI service.
func TestRunSendsNoAIRequest(t *testing.T) {
	withProdCatalog(t)
	p := newPlatform(t)
	rep := newProber(p, &fakeNet{p: p, fam: unlock.FamilyIPv4, dev: "m00"}).Run(context.Background(), Spec{ExitID: "us", Family: unlock.FamilyIPv4, Region: "us",
		Services: []string{"auto-openai", "auto-gemini", "auto-anthropic"}})
	for _, h := range []string{"api.openai.com", "ios.chat.openai.com", "gemini.google.com", "claude.ai", "www.anthropic.com"} {
		if n := p.count(h); n != 0 {
			t.Errorf("%d requests to %s", n, h)
		}
	}
	for _, r := range rep.Results {
		if r.Category != CatFailed {
			t.Errorf("AI result %+v", r)
		}
	}
}

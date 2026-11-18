package probe

import "testing"

func TestProbeScope(t *testing.T) {
	for _, a := range Catalog {
		if a.Global() != (a.ProbeRegions() == nil) {
			t.Fatalf("%s: global %v regions %v", a.Service, a.Global(), a.ProbeRegions())
		}
		if a.Global() && !a.ProbesOn(nil) {
			t.Fatalf("%s: global service must run on any exit", a.Service)
		}
		if !a.Global() && a.ProbesOn(nil) {
			t.Fatalf("%s: regional service ran on an exit without a region", a.Service)
		}
	}
	kktv, _ := Lookup("auto-kktv")
	if kktv.ProbesOn([]string{"jp", "hk"}) || !kktv.ProbesOn([]string{"Taiwan"}) || kktv.InScope("global") || !kktv.InScope("tw") || kktv.InScope("hk") {
		t.Fatal("kktv scope")
	}
	bg, _ := Lookup("bglobal-sea")
	if !bg.ProbesOn([]string{"my"}) || !bg.InScope("sg") {
		t.Fatal("b-global scope")
	}
	nf, _ := Lookup("auto-netflix")
	if !nf.InScope("") || !nf.InScope("global") || nf.InScope("hk") {
		t.Fatal("netflix scope")
	}
}

func TestServiceMatching(t *testing.T) {
	nf, _ := Lookup("auto-netflix")
	for _, d := range []string{"netflix.com", "www.netflix.com", ".nflxvideo.net"} {
		if !nf.MatchesDomain(d) {
			t.Fatalf("netflix domain %s", d)
		}
	}
	for _, d := range []string{"com", "notnetflix.com", "example.com"} {
		if nf.MatchesDomain(d) {
			t.Fatalf("netflix matched %s", d)
		}
	}
	for _, n := range []string{"geosite:netflix", "🎥 Netflix", "Netflix-HK"} {
		if !nf.MatchesName(n) {
			t.Fatalf("netflix name %s", n)
		}
	}
	if nf.MatchesName("Streaming") {
		t.Fatal("generic label matched")
	}
	gm, _ := Lookup("auto-gemini")
	if gm.MatchesDomain("google.com") || gm.MatchesDomain("www.google.com") || !gm.MatchesDomain("gemini.google.com") {
		t.Fatal("shared domain must stand only for the probe host")
	}
	dp, _ := Lookup("auto-disney")
	if !dp.MatchesName("Disney Plus") {
		t.Fatal("joined tokens")
	}
}

func TestReferenceChecksDoNotMatchRules(t *testing.T) {
	for _, a := range Catalog {
		for _, c := range a.Checks {
			if c.Primary {
				continue
			}
			for _, h := range c.Hosts {
				own := false
				for _, p := range a.Checks {
					if p.Primary {
						for _, ph := range p.Hosts {
							own = own || registrable(ph) == registrable(h)
						}
					}
				}
				if !own && a.MatchesDomain(h) {
					t.Fatalf("%s: reference host %s matches its rules", a.Service, h)
				}
			}
		}
	}
	my, _ := Lookup("auto-mytvsuper")
	ab, _ := Lookup("auto-abema")
	viu, _ := Lookup("auto-viu")
	if !viu.MatchesDomain("www.viu.com") || !viu.MatchesName("geosite:viu") || viu.MatchesDomain("mytvsuper.com") || viu.MatchesName("ViuTV") {
		t.Fatal("viu ownership")
	}
	if my.MatchesDomain("viu.com") || my.MatchesName("geosite:viu") || ab.MatchesDomain("nicovideo.jp") || ab.MatchesName("Niconico") {
		t.Fatal("reference platform matched")
	}
	if !my.MatchesDomain("www.mytvsuper.com") || !ab.MatchesDomain("api.abema.io") || !ab.MatchesName("AbemaTV") {
		t.Fatal("primary platform not matched")
	}
	if my.Name != "MyTV SUPER" || ab.Name != "Abema" {
		t.Fatalf("names claim unverified platforms: %q %q", my.Name, ab.Name)
	}
}

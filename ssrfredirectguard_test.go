package main

import "testing"

func srdHasReason(fs []SRDFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestSRDSafeSameHost(t *testing.T) {
	pol := DefaultSRDPolicy()
	req := SRDRequest{
		CurrentURL:  "https://files.example.com/a.jar",
		Location:    "https://files.example.com/cdn/a.jar",
		Hop:         1,
		CarriesAuth: false,
	}
	if f := SRDEvaluateHop(req, pol); len(f) != 0 {
		t.Fatalf("same-host https redirect must pass: %v", f)
	}
}

func TestSRDDowngrade(t *testing.T) {
	pol := DefaultSRDPolicy()
	req := SRDRequest{CurrentURL: "https://files.example.com/a", Location: "http://files.example.com/b", Hop: 1}
	if f := SRDEvaluateHop(req, pol); !srdHasReason(f, SRDReasonDowngradeHTTPS) {
		t.Fatal("https->http downgrade must be flagged")
	}
}

func TestSRDDangerousScheme(t *testing.T) {
	pol := DefaultSRDPolicy()
	for _, loc := range []string{"file:///etc/passwd", "gopher://127.0.0.1:9000"} {
		req := SRDRequest{CurrentURL: "https://x.example.com/a", Location: loc, Hop: 1}
		if f := SRDEvaluateHop(req, pol); !srdHasReason(f, SRDReasonDangerousScheme) {
			t.Fatalf("redirect to %s must be flagged", loc)
		}
	}
}

func TestSRDPrivateTarget(t *testing.T) {
	pol := DefaultSRDPolicy()
	for _, loc := range []string{
		"http://127.0.0.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/x",
		"http://localhost/admin",
	} {
		req := SRDRequest{CurrentURL: "https://cdn.example.com/a", Location: loc, Hop: 1}
		if f := SRDEvaluateHop(req, pol); !srdHasReason(f, SRDReasonTargetPrivate) {
			t.Fatalf("redirect to private target %s must be flagged", loc)
		}
	}
}

func TestSRDCrossHostAuth(t *testing.T) {
	pol := DefaultSRDPolicy()
	req := SRDRequest{
		CurrentURL:  "https://api.example.com/token",
		Location:    "https://evil.example.net/collect",
		Hop:         1,
		CarriesAuth: true,
	}
	if f := SRDEvaluateHop(req, pol); !srdHasReason(f, SRDReasonCrossHostWithAuth) {
		t.Fatal("cross-host redirect carrying auth must be flagged")
	}
}

func TestSRDUserInfo(t *testing.T) {
	pol := DefaultSRDPolicy()
	req := SRDRequest{CurrentURL: "https://x.example.com/a", Location: "https://user:pass@x.example.com/b"}
	if f := SRDEvaluateHop(req, pol); !srdHasReason(f, SRDReasonUserInfoLeak) {
		t.Fatal("userinfo in redirect target must be flagged")
	}
}

func TestSRDTooManyHops(t *testing.T) {
	pol := DefaultSRDPolicy()
	req := SRDRequest{CurrentURL: "https://a.example.com", Location: "https://b.example.com", Hop: 6}
	if f := SRDEvaluateHop(req, pol); !srdHasReason(f, SRDReasonTooManyRedirects) {
		t.Fatal("hop beyond limit must be flagged")
	}
}

func TestSRDAllowlist(t *testing.T) {
	pol := DefaultSRDPolicy()
	pol.RestrictToAllowlist = true
	pol.AllowlistedHosts = []string{"cdn.example.com"}
	ok := SRDRequest{CurrentURL: "https://app.example.com", Location: "https://cdn.example.com/x"}
	if f := SRDEvaluateHop(ok, pol); len(f) != 0 {
		t.Fatalf("allowlisted host must pass: %v", f)
	}
	bad := SRDRequest{CurrentURL: "https://app.example.com", Location: "https://other.example.net/x"}
	if f := SRDEvaluateHop(bad, pol); !srdHasReason(f, SRDReasonOpenRedirectHost) {
		t.Fatal("non-allowlisted host must be flagged")
	}
}

func TestSRDChain(t *testing.T) {
	pol := DefaultSRDPolicy()
	locs := []string{
		"https://files.example.com/b",
		"http://127.0.0.1/leak", // 内网目标
	}
	f := SRDEvaluateChain("https://short.example.com/a", locs, true, pol)
	if !srdHasReason(f, SRDReasonTargetPrivate) {
		t.Fatal("chain ending at private target must be flagged")
	}
}

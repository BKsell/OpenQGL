package main

import "testing"

func rhgHas(fs []RHGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestRHGSameHostOK(t *testing.T) {
	pol := DefaultRHGPolicy()
	hops := []RHGHop{{FromScheme: "https", FromHost: "a.test", ToScheme: "https", ToHost: "a.test", StatusCode: 302}}
	st := RHGRequestState{HasAuthorization: true, HasCookie: true}
	safe, _ := RHGEvaluateChain(hops, st, pol)
	if !safe {
		t.Fatal("same-host redirect keeping creds should pass")
	}
}

func TestRHGAuthCrossHost(t *testing.T) {
	pol := DefaultRHGPolicy()
	hops := []RHGHop{{FromScheme: "https", FromHost: "a.test", ToScheme: "https", ToHost: "cdn.evil.test", StatusCode: 302}}
	st := RHGRequestState{HasAuthorization: true}
	_, fs := RHGEvaluateChain(hops, st, pol)
	if !rhgHas(fs, RHGReasonAuthHeaderCrossHost) {
		t.Fatalf("want auth cross host, got %v", fs)
	}
}

func TestRHGCookieCrossHost(t *testing.T) {
	pol := DefaultRHGPolicy()
	hops := []RHGHop{{FromScheme: "https", FromHost: "mod.test", ToScheme: "https", ToHost: "storage.other.test", StatusCode: 301}}
	st := RHGRequestState{HasCookie: true}
	_, fs := RHGEvaluateChain(hops, st, pol)
	if !rhgHas(fs, RHGReasonCookieCrossHost) {
		t.Fatalf("want cookie cross host, got %v", fs)
	}
}

func TestRHGCustomToken(t *testing.T) {
	pol := DefaultRHGPolicy()
	hops := []RHGHop{{FromScheme: "https", FromHost: "a.test", ToScheme: "https", ToHost: "b.test", StatusCode: 302}}
	st := RHGRequestState{CustomTokenHeaders: []string{"X-Api-Key"}}
	_, fs := RHGEvaluateChain(hops, st, pol)
	if !rhgHas(fs, RHGReasonCustomTokenCrossHost) {
		t.Fatalf("want custom token, got %v", fs)
	}
}

func TestRHGDowngrade(t *testing.T) {
	pol := DefaultRHGPolicy()
	hops := []RHGHop{{FromScheme: "https", FromHost: "a.test", ToScheme: "http", ToHost: "a.test", StatusCode: 302}}
	st := RHGRequestState{HasAuthorization: true}
	_, fs := RHGEvaluateChain(hops, st, pol)
	if !rhgHas(fs, RHGReasonDowngradeToHTTP) {
		t.Fatalf("want downgrade, got %v", fs)
	}
}

func TestRHGSubdomainCrossByDefault(t *testing.T) {
	pol := DefaultRHGPolicy()
	// 默认不允许同注册域子域保留凭据：api.example -> assets.example 仍跨信任
	hops := []RHGHop{{FromScheme: "https", FromHost: "api.example.com", ToScheme: "https",
		ToHost: "assets.example.com", StatusCode: 302}}
	st := RHGRequestState{HasAuthorization: true}
	_, fs := RHGEvaluateChain(hops, st, pol)
	if !rhgHas(fs, RHGReasonAuthHeaderCrossHost) {
		t.Fatalf("want cross-subdomain treated as cross-host by default, got %v", fs)
	}
}

func TestRHGSameRegistrableAllowed(t *testing.T) {
	pol := DefaultRHGPolicy()
	pol.AllowedSameRegistrable = true
	hops := []RHGHop{{FromScheme: "https", FromHost: "api.example.com", ToScheme: "https",
		ToHost: "assets.example.com", StatusCode: 302}}
	st := RHGRequestState{HasAuthorization: true}
	safe, _ := RHGEvaluateChain(hops, st, pol)
	if !safe {
		t.Fatal("same registrable subdomain should pass under policy")
	}
}

func TestRHGBody303(t *testing.T) {
	pol := DefaultRHGPolicy()
	hops := []RHGHop{{FromScheme: "https", FromHost: "a.test", ToScheme: "https", ToHost: "a.test", StatusCode: 303}}
	st := RHGRequestState{HasSensitiveBody: true}
	_, fs := RHGEvaluateChain(hops, st, pol)
	if !rhgHas(fs, RHGReasonBodyKeptOn303) {
		t.Fatalf("want body 303, got %v", fs)
	}
}

func TestRHGTooMany(t *testing.T) {
	pol := DefaultRHGPolicy()
	pol.MaxRedirects = 2
	hops := []RHGHop{
		{FromScheme: "https", FromHost: "a.test", ToScheme: "https", ToHost: "b.test", StatusCode: 302},
		{FromScheme: "https", FromHost: "b.test", ToScheme: "https", ToHost: "c.test", StatusCode: 302},
		{FromScheme: "https", FromHost: "c.test", ToScheme: "https", ToHost: "d.test", StatusCode: 302},
	}
	_, fs := RHGEvaluateChain(hops, RHGRequestState{}, pol)
	if !rhgHas(fs, RHGReasonTooManyRedirects) {
		t.Fatalf("want too many, got %v", fs)
	}
}

func TestRHGLoop(t *testing.T) {
	pol := DefaultRHGPolicy()
	hops := []RHGHop{
		{FromScheme: "https", FromHost: "a.test", ToScheme: "https", ToHost: "b.test", StatusCode: 302},
		{FromScheme: "https", FromHost: "b.test", ToScheme: "https", ToHost: "a.test", StatusCode: 302},
		{FromScheme: "https", FromHost: "a.test", ToScheme: "https", ToHost: "b.test", StatusCode: 302},
	}
	_, fs := RHGEvaluateChain(hops, RHGRequestState{}, pol)
	if !rhgHas(fs, RHGReasonRedirectLoop) {
		t.Fatalf("want loop, got %v", fs)
	}
}

func TestRHGNonHTTPScheme(t *testing.T) {
	pol := DefaultRHGPolicy()
	hops := []RHGHop{{FromScheme: "https", FromHost: "a.test", ToScheme: "file", ToHost: "", StatusCode: 302}}
	_, fs := RHGEvaluateChain(hops, RHGRequestState{}, pol)
	if !rhgHas(fs, RHGReasonNonHTTPSchemeTarget) {
		t.Fatalf("want non-http scheme, got %v", fs)
	}
}

func TestRHGCookieDomainWide(t *testing.T) {
	pol := DefaultRHGPolicy()
	hops := []RHGHop{{FromScheme: "https", FromHost: "api.example.com", ToScheme: "https",
		ToHost: "api.example.com", StatusCode: 302}}
	st := RHGRequestState{HasCookie: true, CookieDomains: []string{"evilwide.xyz"}}
	_, fs := RHGEvaluateChain(hops, st, pol)
	if !rhgHas(fs, RHGReasonCookieDomainWide) {
		t.Fatalf("want wide cookie domain, got %v", fs)
	}
}

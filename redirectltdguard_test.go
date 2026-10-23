package main

import "testing"

func rldHas(fs []RLDFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func rldClient() RLDClient {
	return RLDClient{
		ClientID:      "launcher",
		AllowedHosts:  map[string]bool{"app.test": true, "app.test:8443": true},
		PathPrefixes:  []string{"/auth/callback"},
		AllowLoopback: false,
	}
}

func TestRLDGoodCallback(t *testing.T) {
	pol := DefaultRLDPolicy()
	safe, _ := RLDValidate("https://app.test/auth/callback?code=abc", rldClient(), pol)
	if !safe {
		t.Fatal("valid callback should pass")
	}
}

func TestRLDHostNotAllowed(t *testing.T) {
	pol := DefaultRLDPolicy()
	_, fs := RLDValidate("https://evil.test/auth/callback", rldClient(), pol)
	if !rldHas(fs, RLDReasonHostNotAllowed) {
		t.Fatalf("want host reject, got %v", fs)
	}
}

func TestRLDSuffixNoBypass(t *testing.T) {
	pol := DefaultRLDPolicy()
	_, fs := RLDValidate("https://app.test.evil.test/auth/callback", rldClient(), pol)
	if !rldHas(fs, RLDReasonHostNotAllowed) {
		t.Fatalf("suffix trick must not bypass, got %v", fs)
	}
}

func TestRLDPathPrefixDenied(t *testing.T) {
	pol := DefaultRLDPolicy()
	_, fs := RLDValidate("https://app.test/other", rldClient(), pol)
	if !rldHas(fs, RLDReasonPathPrefixDenied) {
		t.Fatalf("want path deny, got %v", fs)
	}
}

func TestRLDProtocolRelative(t *testing.T) {
	pol := DefaultRLDPolicy()
	_, fs := RLDValidate("//app.test/auth/callback", rldClient(), pol)
	if !rldHas(fs, RLDReasonProtocolRelative) {
		t.Fatalf("want protocol relative, got %v", fs)
	}
}

func TestRLDBackslash(t *testing.T) {
	pol := DefaultRLDPolicy()
	_, fs := RLDValidate(`/\app.test/auth/callback`, rldClient(), pol)
	if !rldHas(fs, RLDReasonBackslashHost) && !rldHas(fs, RLDReasonProtocolRelative) {
		t.Fatalf("want backslash confusion, got %v", fs)
	}
}

func TestRLDUserInfoSpoof(t *testing.T) {
	pol := DefaultRLDPolicy()
	_, fs := RLDValidate("https://app.test@evil.test/auth/callback", rldClient(), pol)
	if !rldHas(fs, RLDReasonUserInfo) {
		t.Fatalf("want userinfo, got %v", fs)
	}
}

func TestRLDLoopbackBlocked(t *testing.T) {
	pol := DefaultRLDPolicy()
	_, fs := RLDValidate("http://127.0.0.1:8080/auth/callback", rldClient(), pol)
	if !rldHas(fs, RLDReasonLocalOrMetadata) {
		t.Fatalf("want loopback block, got %v", fs)
	}
}

func TestRLDLoopbackAllowed(t *testing.T) {
	pol := DefaultRLDPolicy()
	c := rldClient()
	c.AllowLoopback = true
	c.AllowedHosts["127.0.0.1:8080"] = true
	c.PathPrefixes = []string{"/"}
	safe, _ := RLDValidate("http://127.0.0.1:8080/auth/callback", c, pol)
	if !safe {
		t.Fatal("loopback client flow should pass")
	}
}

func TestRLDMetadata(t *testing.T) {
	pol := DefaultRLDPolicy()
	c := rldClient()
	c.AllowedHosts["169.254.169.254"] = true
	c.PathPrefixes = []string{"/"}
	_, fs := RLDValidate("http://169.254.169.254/latest/meta-data", c, pol)
	if !rldHas(fs, RLDReasonLocalOrMetadata) {
		t.Fatalf("want metadata block, got %v", fs)
	}
}

func TestRLDNonHTTPScheme(t *testing.T) {
	pol := DefaultRLDPolicy()
	_, fs := RLDValidate("javascript:alert(1)", rldClient(), pol)
	if !rldHas(fs, RLDReasonNonHTTPScheme) {
		t.Fatalf("want non-http scheme, got %v", fs)
	}
}

func TestRLDEmpty(t *testing.T) {
	pol := DefaultRLDPolicy()
	_, fs := RLDValidate("   ", rldClient(), pol)
	if !rldHas(fs, RLDReasonEmpty) {
		t.Fatalf("want empty, got %v", fs)
	}
}

func TestRLDPortMatters(t *testing.T) {
	pol := DefaultRLDPolicy()
	_, fs := RLDValidate("https://app.test:9000/auth/callback", rldClient(), pol)
	if !rldHas(fs, RLDReasonHostNotAllowed) {
		t.Fatalf("different port must be distinct host, got %v", fs)
	}
}

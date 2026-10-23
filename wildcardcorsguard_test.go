package main

import "testing"

func TestWCHealthyExactOrigin(t *testing.T) {
	allow := map[string]bool{"https://app.example.com": true}
	r := WCResponse{AllowOrigin: "https://app.example.com",
		AllowCredentials: true, RequestOrigin: "https://app.example.com"}
	if safe, _ := WCAudit(r, allow); !safe {
		t.Fatal("exact allowlisted credentialed origin should pass")
	}
}

func TestWCWildcardWithCredentials(t *testing.T) {
	r := WCResponse{AllowOrigin: "*", AllowCredentials: true}
	_, fs := WCAudit(r, map[string]bool{})
	if !WCHasReason(fs, WCReasonWildcardWithCredentials) {
		t.Fatalf("ACAO * with credentials must flag: %v", fs)
	}
}

func TestWCReflectsAnyOrigin(t *testing.T) {
	r := WCResponse{AllowOrigin: "https://evil.example",
		AllowCredentials: true, RequestOrigin: "https://evil.example"}
	_, fs := WCAudit(r, map[string]bool{})
	if !WCHasReason(fs, WCReasonReflectsAnyOrigin) {
		t.Fatalf("reflecting arbitrary origin with creds must flag: %v", fs)
	}
}

func TestWCNullOrigin(t *testing.T) {
	r := WCResponse{AllowOrigin: "null"}
	_, fs := WCAudit(r, map[string]bool{})
	if !WCHasReason(fs, WCReasonNullOrigin) {
		t.Fatalf("null origin must flag: %v", fs)
	}
}

func TestWCWildcardHeadersWithCreds(t *testing.T) {
	r := WCResponse{AllowOrigin: "https://app.example", AllowCredentials: true,
		AllowHeaders: "X-Custom, *"}
	_, fs := WCAudit(r, map[string]bool{"https://app.example": true})
	if !WCHasReason(fs, WCReasonWildcardHeadersCreds) {
		t.Fatalf("wildcard allowed-headers with creds must flag: %v", fs)
	}
}

func TestWCExactSuffixMatch(t *testing.T) {
	if !WCAllowedByExactSuffix("https://example.com", "https", "example.com") {
		t.Fatal("apex should match")
	}
	if !WCAllowedByExactSuffix("https://a.example.com", "https", "example.com") {
		t.Fatal("subdomain should match")
	}
	if WCAllowedByExactSuffix("https://evil-example.com", "https", "example.com") {
		t.Fatal("evil-example.com substring must NOT match")
	}
	if WCAllowedByExactSuffix("https://example.com.evil.io", "https", "example.com") {
		t.Fatal("suffix without dot boundary must NOT match")
	}
}

func TestWCWeakSuffixRule(t *testing.T) {
	for _, rule := range []string{"", "*", "com", "*.example.com"} {
		if !WCAuditSuffixRule(rule) {
			t.Fatalf("rule %q should be considered weak", rule)
		}
	}
	if WCAuditSuffixRule("example.com") {
		t.Fatal("specific domain rule should be acceptable")
	}
}

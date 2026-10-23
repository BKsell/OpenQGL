package main

import "testing"

func cpHasReason(fs []CPFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestCPHostPrefixValid(t *testing.T) {
	pol := DefaultCPPolicy()
	raw := "__Host-session=abc; Path=/; Secure; SameSite=Strict"
	if f := CPValidateRawSetCookie(raw, pol); len(f) != 0 {
		t.Fatalf("valid __Host- cookie must pass: %v", f)
	}
}

func TestCPHostPrefixViolations(t *testing.T) {
	pol := DefaultCPPolicy()
	// 缺 Secure。
	if f := CPValidateRawSetCookie("__Host-s=1; Path=/", pol); !cpHasReason(f, CPReasonHostNotSecure) {
		t.Fatal("__Host- without Secure must fail")
	}
	// Path 不是 /。
	if f := CPValidateRawSetCookie("__Host-s=1; Path=/app; Secure", pol); !cpHasReason(f, CPReasonHostBadPath) {
		t.Fatal("__Host- with Path=/app must fail")
	}
	// 带 Domain。
	if f := CPValidateRawSetCookie("__Host-s=1; Path=/; Secure; Domain=.example.com", pol);
		!cpHasReason(f, CPReasonHostHasDomain) {
		t.Fatal("__Host- with Domain must fail")
	}
}

func TestCPSecurePrefix(t *testing.T) {
	pol := DefaultCPPolicy()
	if f := CPValidateRawSetCookie("__Secure-id=9; Secure", pol); len(f) != 0 {
		t.Fatalf("valid __Secure- must pass: %v", f)
	}
	if f := CPValidateRawSetCookie("__Secure-id=9", pol); !cpHasReason(f, CPReasonSecureNotSecure) {
		t.Fatal("__Secure- without Secure must fail")
	}
}

func TestCPSameSite(t *testing.T) {
	pol := DefaultCPPolicy()
	if f := CPValidateRawSetCookie("sid=1; SameSite=Bogus", pol); !cpHasReason(f, CPReasonBadSameSite) {
		t.Fatal("invalid SameSite value must fail")
	}
	if f := CPValidateRawSetCookie("sid=1; SameSite=None", pol); !cpHasReason(f, CPReasonSameSiteNoneHTTP) {
		t.Fatal("SameSite=None without Secure must fail")
	}
	if f := CPValidateRawSetCookie("sid=1; Secure; SameSite=None", pol); len(f) != 0 {
		t.Fatalf("SameSite=None + Secure must pass: %v", f)
	}
}

func TestCPResponseSplitting(t *testing.T) {
	pol := DefaultCPPolicy()
	raw := "sid=1\r\nSet-Cookie: admin=1"
	if f := CPValidateRawSetCookie(raw, pol); !cpHasReason(f, CPReasonCRLF) {
		t.Fatal("CRLF response splitting must be flagged")
	}
}

func TestCPEmptyName(t *testing.T) {
	pol := DefaultCPPolicy()
	if f := CPValidateRawSetCookie("=value", pol); !cpHasReason(f, CPReasonEmptyName) {
		t.Fatal("empty cookie name must fail")
	}
}

func TestCPIsSafe(t *testing.T) {
	if !CPIsSafe("normal=1; Path=/; HttpOnly; SameSite=Lax") {
		t.Fatal("ordinary cookie should be safe")
	}
	if CPIsSafe("__Host-x=1; Path=/") {
		t.Fatal("non-secure host cookie must not be safe")
	}
}

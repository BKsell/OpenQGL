package main

import "testing"

func TestSKHealthyCookie(t *testing.T) {
	c := SKCookie{Name: "sid", Value: "abc", IsSessionToken: true,
		HttpOnly: true, Secure: true, SameSite: "Lax", MaxAgeSec: 3600}
	if safe, _ := SKAuditCookie(c); !safe {
		t.Fatal("hardened session cookie should pass")
	}
}

func TestSKMissingFlags(t *testing.T) {
	c := SKCookie{Name: "sid", Value: "abc", SameSite: "None", MaxAgeSec: 3600}
	_, fs := SKAuditCookie(c)
	for _, r := range []string{SKReasonMissingHttpOnly, SKReasonMissingSecure, SKReasonSameSiteWeak} {
		if !SKHasReason(fs, r) {
			t.Fatalf("want %s: %v", r, fs)
		}
	}
}

func TestSKSameSiteNoneRejected(t *testing.T) {
	c := SKCookie{Name: "sid", Value: "x", HttpOnly: true, Secure: true,
		SameSite: "None", MaxAgeSec: 60}
	_, fs := SKAuditCookie(c)
	if !SKHasReason(fs, SKReasonSameSiteWeak) {
		t.Fatalf("SameSite=None weak for session cookie: %v", fs)
	}
}

func TestSKNeverExpires(t *testing.T) {
	c := SKCookie{Name: "sid", Value: "x", HttpOnly: true, Secure: true,
		SameSite: "Strict", MaxAgeSec: 365 * 24 * 3600}
	_, fs := SKAuditCookie(c)
	if !SKHasReason(fs, SKReasonNeverExpires) {
		t.Fatalf("year-long max-age should be flagged: %v", fs)
	}
}

func TestSKRefreshMixedInSession(t *testing.T) {
	c := SKCookie{Name: "tok", Value: "x", HttpOnly: true, Secure: true,
		SameSite: "Strict", MaxAgeSec: 60,
		IsSessionToken: true, IsRefreshToken: true}
	_, fs := SKAuditCookie(c)
	if !SKHasReason(fs, SKReasonRefreshInSession) {
		t.Fatalf("refresh token must not share session cookie: %v", fs)
	}
}

func TestSKEmptyValue(t *testing.T) {
	c := SKCookie{Name: "sid", Value: "", HttpOnly: true, Secure: true,
		SameSite: "Lax"}
	_, fs := SKAuditCookie(c)
	if !SKHasReason(fs, SKReasonEmptyValue) {
		t.Fatalf("empty cookie value flagged: %v", fs)
	}
}

func TestSKRotationOK(t *testing.T) {
	if ok, _ := SKCheckRotation("pre123", "post456"); !ok {
		t.Fatal("session id should rotate after login")
	}
}

func TestSKFixation(t *testing.T) {
	ok, fs := SKCheckRotation("attacker-preset-id", "attacker-preset-id")
	if ok || !SKHasReason(fs, SKReasonFixation) {
		t.Fatalf("unchanged session id is fixation: ok=%v %v", ok, fs)
	}
}

func TestSKNoPreSessionOK(t *testing.T) {
	if ok, _ := SKCheckRotation("", "newid"); !ok {
		t.Fatal("no pre-login session is normal")
	}
}

func TestSKSessionScopedMaxAgeOK(t *testing.T) {
	c := SKCookie{Name: "sid", Value: "x", HttpOnly: true, Secure: true,
		SameSite: "Lax", MaxAgeSec: -1}
	if safe, _ := SKAuditCookie(c); !safe {
		t.Fatal("session-scoped cookie (MaxAge=-1) acceptable")
	}
}

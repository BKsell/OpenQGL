package main

import "testing"

func cdpHasReason(fs []CDPFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestCDPScanSecretKV(t *testing.T) {
	pol := DefaultCDPPolicy()
	cases := []string{
		"accessToken=abcdef0123456789",
		`"client_secret": "shh-1234567890"`,
		"password: hunter2hunter2",
		"Authorization=BearerXYZ123",
	}
	for _, c := range cases {
		if f := CDPScan(c, pol); !cdpHasReason(f, CDPReasonSecretKeyValue) {
			t.Fatalf("secret kv must be flagged: %q", c)
		}
	}
}

func TestCDPScanBearer(t *testing.T) {
	pol := DefaultCDPPolicy()
	if f := CDPScan("GET /x HTTP/1.1\r\nAuthorization: Bearer abc123def456", pol);
		!cdpHasReason(f, CDPReasonBearerToken) {
		t.Fatal("bearer token must be flagged")
	}
}

func TestCDPScanBasic(t *testing.T) {
	pol := DefaultCDPPolicy()
	if f := CDPScan("Proxy-Authorization: Basic dXNlcjpwYXNz", pol);
		!cdpHasReason(f, CDPReasonBasicAuth) {
		t.Fatal("basic auth must be flagged")
	}
}

func TestCDPScanJWT(t *testing.T) {
	pol := DefaultCDPPolicy()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	if f := CDPScan("token="+jwt, pol); !cdpHasReason(f, CDPReasonJWTLike) {
		t.Fatal("jwt-like string must be flagged")
	}
}

func TestCDPScanHomePath(t *testing.T) {
	pol := DefaultCDPPolicy()
	text := `dump: C:\Users\CaiJingjie\AppData\Local\game\hs_err.log`
	f := CDPScan(text, pol)
	if !cdpHasReason(f, CDPReasonHomePathUser) {
		t.Fatal("home path username must be flagged")
	}
}

func TestCDPRedactKV(t *testing.T) {
	pol := DefaultCDPPolicy()
	out := CDPRedact("accessToken=supersecretvalue1234", pol)
	if cdpHasSubstr(out, "supersecretvalue1234") {
		t.Fatalf("secret value must be redacted: %q", out)
	}
	if !cdpHasSubstr(out, "accessToken=") {
		t.Fatalf("key must be preserved: %q", out)
	}
}

func TestCDPRedactBearer(t *testing.T) {
	pol := DefaultCDPPolicy()
	out := CDPRedact("Authorization: Bearer abcdef123456", pol)
	if cdpHasSubstr(out, "abcdef123456") {
		t.Fatalf("bearer credential must be redacted: %q", out)
	}
}

func TestCDPRedactJWT(t *testing.T) {
	pol := DefaultCDPPolicy()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.aaaaaaaaaaaaaaaaaaaaaaaaaa"
	out := CDPRedact("jwt=" + jwt, pol)
	if cdpHasSubstr(out, "eyJhbGci") {
		t.Fatalf("jwt must be redacted: %q", out)
	}
}

func TestCDPRedactHomePath(t *testing.T) {
	pol := DefaultCDPPolicy()
	out := CDPRedact(`path=C:\Users\CaiJingjie\AppData\roaming`, pol)
	if cdpHasSubstr(out, "CaiJingjie") {
		t.Fatalf("username in home path must be redacted: %q", out)
	}
}

func TestCDPClean(t *testing.T) {
	pol := DefaultCDPPolicy()
	clean := "panic: runtime error at mod/launch.go:42 invalid memory address"
	if f := CDPScan(clean, pol); len(f) != 0 {
		t.Fatalf("ordinary panic text must pass: %v", f)
	}
}

func cdpHasSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

package main

import "testing"

func uiHasReason(fs []UIFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestUICleanURL(t *testing.T) {
	pol := DefaultUIPolicy()
	for _, u := range []string{
		"https://files.example.com/a/b.jar",
		"http://127.0.0.1:8080/x",
		"https://[2001:db8::1]:9000/path?q=1",
	} {
		if f := UIEvaluate(u, pol); len(f) != 0 {
			t.Fatalf("clean url %q must pass: %v", u, f)
		}
	}
}

func TestUIEmbeddedPassword(t *testing.T) {
	pol := DefaultUIPolicy()
	u := "https://ci:secretToken@repo.example.com/lib.jar"
	f := UIEvaluate(u, pol)
	if !uiHasReason(f, UIReasonEmbeddedCredentials) || !uiHasReason(f, UIReasonPasswordPresent) {
		t.Fatalf("embedded password must be flagged: %v", f)
	}
}

func TestUIEmbeddedUsernameOnly(t *testing.T) {
	pol := DefaultUIPolicy()
	u := "https://oauth2@files.example.com/x"
	if f := UIEvaluate(u, pol); !uiHasReason(f, UIReasonEmbeddedCredentials) {
		t.Fatal("username-only userinfo must be flagged by default")
	}
}

func TestUIStripUserInfo(t *testing.T) {
	stripped, ok := UIStripUserInfo("https://ci:tok@repo.example.com/lib.jar")
	if !ok {
		t.Fatal("strip must succeed")
	}
	if stripped != "https://repo.example.com/lib.jar" {
		t.Fatalf("stripped url wrong: %q", stripped)
	}
	v6, ok2 := UIStripUserInfo("https://u:p@[2001:db8::1]:9000/x")
	if !ok2 || v6 != "https://[2001:db8::1]:9000/x" {
		t.Fatalf("ipv6 strip wrong: %q ok=%v", v6, ok2)
	}
}

func TestUISafeDisplay(t *testing.T) {
	d := UISafeDisplay("https://ci:tok@repo.example.com/lib.jar")
	if uiSubstr(d, "tok") {
		t.Fatalf("password must be masked in display: %q", d)
	}
	if !uiSubstr(d, "repo.example.com") {
		t.Fatalf("host must remain in display: %q", d)
	}
}

func TestUIDangerousScheme(t *testing.T) {
	pol := DefaultUIPolicy()
	if f := UIEvaluate("file:///etc/passwd", pol); !uiHasReason(f, UIReasonDangerousScheme) {
		t.Fatal("file scheme must be flagged")
	}
}

func TestUIControlChar(t *testing.T) {
	pol := DefaultUIPolicy()
	if f := UIEvaluate("https://x.example.com/a\r\nX:y", pol); !uiHasReason(f, UIReasonControlChar) {
		t.Fatal("CRLF in url must be flagged")
	}
}

func TestUIIsSafe(t *testing.T) {
	if !UIIsSafe("https://cdn.example.com/file.jar") {
		t.Fatal("normal url must be safe")
	}
	if UIIsSafe("https://u:p@cdn.example.com/f") {
		t.Fatal("url with credentials must not be safe")
	}
}

func uiSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

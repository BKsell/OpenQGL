package main

import "testing"

// hiContainsReason 在 findings 中查找指定原因（避开 worldmeta_test.go 的同名 helper）。
func hiContainsReason(findings []HIFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestHIHeaderNameValid(t *testing.T) {
	cases := []struct {
		name    string
		wantOK  bool
	}{
		{"X-Custom", true},
		{"Content-Type", true},
		{"x-maven-meta.2", true},
		{"", false},
		{"Bad Name", false},
		{"Bad:Name", false},
		{"Header\x00", false},
	}
	for _, c := range cases {
		reason, _ := HIValidateHeaderName(c.name)
		gotOK := reason == ""
		if gotOK != c.wantOK {
			t.Fatalf("name %q wantOK=%v got reason=%q", c.name, c.wantOK, reason)
		}
	}
}

func TestHIHeaderValueCRLF(t *testing.T) {
	pol := DefaultHIPolicy()
	bad := []string{
		"a\r\nInjected: yes",
		"a\rb",
		"a\nb",
		"x\x00y",
		" leading-space-fold",
		"trailing-space ",
		"tab\there",
		"caf\x01",
		"nonascii\xc3\xa9",
	}
	for _, v := range bad {
		if reason, _ := HIValidateHeaderValue("X-Custom", v, pol); reason == "" {
			t.Fatalf("expected rejection for %q", v)
		}
	}
}

func TestHIHeaderValueAllowed(t *testing.T) {
	pol := DefaultHIPolicy()
	good := []string{
		"OpenQGL/1.0",
		"gzip, deflate",
		"token; value=\"quoted\"",
		"2026-10-23T08:00:00Z",
	}
	for _, v := range good {
		if reason, _ := HIValidateHeaderValue("X-Custom", v, pol); reason != "" {
			t.Fatalf("expected allow for %q got %q", v, reason)
		}
	}
}

func TestHIValueTooLong(t *testing.T) {
	pol := DefaultHIPolicy()
	long := ""
	for i := 0; i < pol.MaxHeaderValueBytes+1; i++ {
		long += "a"
	}
	if reason, _ := HIValidateHeaderValue("X-Custom", long, pol); reason != HIReasonValueTooLong {
		t.Fatalf("expected too-long, got %q", reason)
	}
}

func TestHIForbiddenClientHeaders(t *testing.T) {
	pol := DefaultHIPolicy()
	findings := HICheckRequestHeaders(map[string][]string{
		"X-Forwarded-For": {"1.2.3.4"},
		"X-Real-IP":       {"1.2.3.4"},
		"Host":            {"evil.example"},
		"X-Safe":          {"ok"},
	}, pol)
	if !hiContainsReason(findings, HIReasonSpoofedForwarded) {
		t.Fatal("expected spoofed-forwarded finding")
	}
	if !hiContainsReason(findings, HIReasonHostForbidden) {
		t.Fatal("expected host-forbidden finding")
	}
}

func TestHIMapClean(t *testing.T) {
	pol := DefaultHIPolicy()
	findings := HICheckHeaderMap(map[string]string{
		"X-Custom":   "value1",
		"User-Agent": "OpenQGL/1.0",
	}, pol)
	if len(findings) != 0 {
		t.Fatalf("expected clean, got %#v", findings)
	}
}

func TestHIMapInjectionCaught(t *testing.T) {
	pol := DefaultHIPolicy()
	findings := HICheckHeaderMap(map[string]string{
		"X-Trace": "abc\r\nSet-Cookie: x=1",
	}, pol)
	if !hiContainsReason(findings, HIReasonCRLF) {
		t.Fatalf("expected CRLF finding, got %#v", findings)
	}
}

func TestHITooManyValues(t *testing.T) {
	pol := DefaultHIPolicy()
	values := make([]string, pol.MaxValuesPerHeader+1)
	for i := range values {
		values[i] = "v"
	}
	findings := HICheckRequestHeaders(map[string][]string{"X-Multi": values}, pol)
	if !hiContainsReason(findings, HIReasonTooManyValues) {
		t.Fatalf("expected too-many-values, got %#v", findings)
	}
}

func TestHITotalSizeCap(t *testing.T) {
	pol := DefaultHIPolicy()
	pol.MaxHeaderTotalBytes = 10
	findings := HICheckHeaderMap(map[string]string{"X-A": "abcdefghijklmnop"}, pol)
	if !hiContainsReason(findings, HIReasonMapTooLarge) {
		t.Fatalf("expected map-too-large, got %#v", findings)
	}
}

func TestHISafeHeaderValueSanitize(t *testing.T) {
	out, changed := HISafeHeaderValue("  a\r\nb\x00c\td  ")
	if !changed {
		t.Fatal("expected changed=true")
	}
	for i := 0; i < len(out); i++ {
		if out[i] == '\r' || out[i] == '\n' || out[i] == 0 {
			t.Fatalf("sanitized value still contains control byte: %q", out)
		}
	}
	if out == "" {
		t.Fatal("sanitized value unexpectedly empty")
	}
}

func TestHIAllowNonASCIIWhenEnabled(t *testing.T) {
	pol := DefaultHIPolicy()
	pol.AllowNonASCII = true
	pol.AllowTabInValue = true
	if reason, _ := HIValidateHeaderValue("X-Custom", "caf\xc3\xa9\tx", pol); reason != "" {
		t.Fatalf("expected allow with relaxed policy, got %q", reason)
	}
}

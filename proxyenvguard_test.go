package main

import "testing"

func pxeHasReason(fs []PXEFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPXEProxySafe(t *testing.T) {
	pol := DefaultPXEPolicy()
	if f := PXEEvaluateProxy("HTTPS_PROXY", "http://proxy.corp.example.com:8080", pol); len(f) != 0 {
		t.Fatalf("normal corporate proxy must pass: %v", f)
	}
}

func TestPXEProxyPrivate(t *testing.T) {
	pol := DefaultPXEPolicy()
	for _, v := range []string{
		"http://127.0.0.1:8080",
		"http://10.0.0.5:3128",
		"socks5://192.168.1.10:1080",
		"http://[::1]:8080",
	} {
		if f := PXEEvaluateProxy("HTTP_PROXY", v, pol); !pxeHasReason(f, PXEReasonProxyToPrivate) {
			t.Fatalf("private proxy %q must be flagged", v)
		}
	}
}

func TestPXEProxyEmbeddedCreds(t *testing.T) {
	pol := DefaultPXEPolicy()
	v := "http://user:pass@proxy.example.com:8080"
	if f := PXEEvaluateProxy("HTTP_PROXY", v, pol); !pxeHasReason(f, PXEReasonEmbeddedCreds) {
		t.Fatal("proxy uri with userinfo must be flagged")
	}
}

func TestPXEProxyBadScheme(t *testing.T) {
	pol := DefaultPXEPolicy()
	if f := PXEEvaluateProxy("ALL_PROXY", "file:///etc/passwd", pol);
		!pxeHasReason(f, PXEReasonDangerousScheme) {
		t.Fatal("file:// proxy must be flagged")
	}
}

func TestPXEProxyIPv6(t *testing.T) {
	pol := DefaultPXEPolicy()
	if f := PXEEvaluateProxy("HTTPS_PROXY", "http://[2001:db8::1]:8080", pol); len(f) != 0 {
		t.Fatalf("public ipv6 proxy must pass: %v", f)
	}
}

func TestPXENoProxyWildcard(t *testing.T) {
	pol := DefaultPXEPolicy()
	if f := PXEEvaluateNoProxy("*", pol); !pxeHasReason(f, PXEReasonNoProxyWildcard) {
		t.Fatal("NO_PROXY=* must be flagged")
	}
}

func TestPXENoProxyTLD(t *testing.T) {
	pol := DefaultPXEPolicy()
	if f := PXEEvaluateNoProxy("com, cn", pol); !pxeHasReason(f, PXEReasonNoProxyOverbroad) {
		t.Fatal("NO_PROXY containing bare TLD must be flagged")
	}
	if f := PXEEvaluateNoProxy(".example.com", pol); len(f) != 0 {
		t.Fatalf("specific suffix .example.com must pass: %v", f)
	}
}

func TestPXEControlChar(t *testing.T) {
	pol := DefaultPXEPolicy()
	if f := PXEEvaluateProxy("HTTP_PROXY", "http://proxy.example.com\r\nX: y", pol);
		!pxeHasReason(f, PXEReasonControlChar) {
		t.Fatal("CRLF in proxy value must be flagged")
	}
}

func TestPXEIsSafe(t *testing.T) {
	if !PXEIsSafe("http://proxy.example.com:8080", "localhost,127.0.0.1") {
		t.Fatal("normal proxy + local no_proxy should be safe")
	}
	if PXEIsSafe("http://127.0.0.1:8080", "") {
		t.Fatal("loopback proxy must not be safe")
	}
}

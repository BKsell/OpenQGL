package main

import "testing"

func TestILCanonicalDecimal(t *testing.T) {
	r := ILNormalizeHost("52.84.1.9")
	if !r.IsIP || r.Canonical4 != "52.84.1.9" || r.Class != HSIPPublic {
		t.Fatalf("canonical public ip wrong: %+v", r)
	}
	if len(r.Reasons) != 0 {
		t.Fatalf("canonical ip must have no ambiguity reasons: %+v", r)
	}
}

func TestILDecimalIntegerLoopback(t *testing.T) {
	r := ILNormalizeHost("2130706433") // 0x7F000001
	if !r.IsIP || r.Canonical4 != "127.0.0.1" || r.Class != HSIPLoopback {
		t.Fatalf("decimal integer must normalize to loopback: %+v", r)
	}
	if !ILHasReason(r, ILReasonAmbiguousEncoding) {
		t.Fatalf("integer form must be flagged non-canonical: %+v", r)
	}
}

func TestILOctalLoopback(t *testing.T) {
	r := ILNormalizeHost("0177.0.0.1")
	if !r.IsIP || r.Canonical4 != "127.0.0.1" {
		t.Fatalf("octal 0177 must normalize to 127: %+v", r)
	}
	if !ILHasReason(r, ILReasonAmbiguousEncoding) {
		t.Fatalf("octal form must be flagged: %+v", r)
	}
}

func TestILHexLoopback(t *testing.T) {
	r := ILNormalizeHost("0x7f.0.0.1")
	if !r.IsIP || r.Canonical4 != "127.0.0.1" {
		t.Fatalf("hex segment must normalize: %+v", r)
	}
	if r.Class != HSIPLoopback {
		t.Fatal("hex loopback must classify as loopback")
	}
}

func TestILHexInteger(t *testing.T) {
	r := ILNormalizeHost("0x7f000001")
	if !r.IsIP || r.Canonical4 != "127.0.0.1" {
		t.Fatalf("hex integer must normalize to loopback: %+v", r)
	}
}

func TestILIPv6Loopback(t *testing.T) {
	for _, h := range []string{"::1", "[::1]", "0:0:0:0:0:0:0:1"} {
		r := ILNormalizeHost(h)
		if !r.IsIP || r.Class != HSIPLoopback {
			t.Fatalf("%s must be ipv6 loopback: %+v", h, r)
		}
	}
}

func TestILIPv6MappedPrivate(t *testing.T) {
	r := ILNormalizeHost("::ffff:192.168.0.1")
	if !r.IsIP || r.Class != HSIPPrivate {
		t.Fatalf("mapped private v4 must classify private: %+v", r)
	}
	if !ILHasReason(r, ILReasonIPv6MappedPrivate) {
		t.Fatalf("mapped form must be flagged: %+v", r)
	}
}

func TestILIPv4CompatLoopback(t *testing.T) {
	r := ILNormalizeHost("::127.0.0.1")
	if !r.IsIP || r.Class != HSIPLoopback {
		t.Fatalf("compatible ::127.0.0.1 must be loopback: %+v", r)
	}
}

func TestILBracketedMapped(t *testing.T) {
	r := ILNormalizeHost("[::ffff:169.254.169.254]")
	if !r.IsIP || r.Class != HSIPLinkLocal {
		t.Fatalf("bracketed mapped metadata must be link-local: %+v", r)
	}
}

func TestILHostnameNotIP(t *testing.T) {
	r := ILNormalizeHost("api.example.com")
	if r.IsIP {
		t.Fatal("a hostname must not be treated as ip literal")
	}
}

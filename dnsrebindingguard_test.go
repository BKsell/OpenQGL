package main

import "testing"

func TestDRGParseIPv4(t *testing.T) {
	cases := []struct {
		in  string
		ok  bool
		a   byte
	}{
		{"8.8.8.8", true, 8},
		{"169.254.169.254", true, 169},
		{"256.1.1.1", false, 0},
		{"1.2.3", false, 0},
		{"1.2.3.4.5", false, 0},
		{"a.b.c.d", false, 0},
	}
	for _, c := range cases {
		ip, ok := drgParseIPv4(c.in)
		if ok != c.ok {
			t.Fatalf("%s ok=%v want %v", c.in, ok, c.ok)
		}
		if ok && ip[0] != c.a {
			t.Fatalf("%s first octet=%d want %d", c.in, ip[0], c.a)
		}
	}
}

func TestDRGExpandIPv6(t *testing.T) {
	g, ok := drgExpandIPv6("::1")
	if !ok || g[7] != 1 {
		t.Fatalf("::1 expand wrong: %v %v", g, ok)
	}
	g2, ok2 := drgExpandIPv6("fc00::1")
	if !ok2 || g2[0]&0xfe00 != 0xfc00 {
		t.Fatalf("fc00::1 expand wrong")
	}
	if _, ok3 := drgExpandIPv6("1::2::3"); ok3 {
		t.Fatal("double :: must be rejected")
	}
}

func TestDRGClassify(t *testing.T) {
	want := map[string]DRGClass{
		"127.0.0.1":         DRGClassLoopback,
		"10.0.0.9":          DRGClassPrivate,
		"192.168.1.1":       DRGClassPrivate,
		"172.20.0.1":        DRGClassPrivate,
		"172.32.0.1":        DRGClassPublic,
		"169.254.169.254":   DRGClassMetadata,
		"169.254.10.10":     DRGClassLinkLocal,
		"::1":               DRGClassLoopback,
		"fd00::1":           DRGClassPrivate,
		"fe80::1":           DRGClassLinkLocal,
		"2606:4700::1":      DRGClassPublic,
	}
	for addr, cls := range want {
		got, ok := drgClassifyIP(addr)
		if !ok {
			t.Fatalf("%s should parse", addr)
		}
		if got != cls {
			t.Fatalf("%s class=%d want %d", addr, got, cls)
		}
	}
	if _, ok := drgClassifyIP("not-an-ip"); ok {
		t.Fatal("bad literal must fail")
	}
}

func TestDRGZeroTTL(t *testing.T) {
	pol := DefaultDRGPolicy()
	f := DRGEvaluateAnswer("cdn.example.com", []string{"8.8.8.8"}, 0, pol)
	if !drgHasReason(f, DRGReasonZeroTTL) {
		t.Fatal("zero TTL must be rejected")
	}
}

func TestDRGMixedTrust(t *testing.T) {
	pol := DefaultDRGPolicy()
	f := DRGEvaluateAnswer("cdn.example.com", []string{"8.8.8.8", "127.0.0.1"}, 60, pol)
	if !drgHasReason(f, DRGReasonLoopback) || !drgHasReason(f, DRGReasonMixedTrust) {
		t.Fatalf("mixed trust answer not flagged: %v", f)
	}
}

func TestDRGMetadata(t *testing.T) {
	pol := DefaultDRGPolicy()
	f := DRGEvaluateAnswer("api.example.com", []string{"169.254.169.254"}, 60, pol)
	if !drgHasReason(f, DRGReasonMetadata) {
		t.Fatal("cloud metadata address must be flagged")
	}
}

func TestDRGNoAddresses(t *testing.T) {
	pol := DefaultDRGPolicy()
	if f := DRGEvaluateAnswer("x", nil, 60, pol); !drgHasReason(f, DRGReasonNoAddresses) {
		t.Fatal("empty answers must be flagged")
	}
}

func TestDRGConsistentResolution(t *testing.T) {
	pol := DefaultDRGPolicy()
	host := "files.example.com"
	checked := []string{"203.0.113.5"}
	if f := DRGCompareResolutions(host, checked, []string{"203.0.113.5"}, pol); len(f) != 0 {
		t.Fatal("identical resolution must be allowed")
	}
	// 校验时公网，连接时环回：典型 rebinding。
	if f := DRGCompareResolutions(host, checked, []string{"127.0.0.1"}, pol); !drgHasReason(f, DRGReasonInconsistent) {
		t.Fatal("rebinding to loopback must be flagged")
	}
	// 地址集合顺序不同但内容一致应放行。
	if f := DRGCompareResolutions(host, []string{"203.0.113.5", "203.0.113.6"},
		[]string{"203.0.113.6", "203.0.113.5"}, pol); len(f) != 0 {
		t.Fatal("order-independent equal sets must be allowed")
	}
}

func TestDRGIsSafe(t *testing.T) {
	if !DRGIsSafe("cdn.example.com", []string{"203.0.113.9"}, 300) {
		t.Fatal("public answer with healthy TTL should be safe")
	}
	if DRGIsSafe("cdn.example.com", []string{"10.0.0.1"}, 300) {
		t.Fatal("private answer must not be safe")
	}
}

func drgHasReason(fs []DRGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

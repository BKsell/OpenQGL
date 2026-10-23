package main

import "testing"

func TestHSClassifyLoopback(t *testing.T) {
	if HSClassifyIP4("127.0.0.1") != HSIPLoopback {
		t.Fatal("127/8 should be loopback")
	}
}

func TestHSClassifyPrivate(t *testing.T) {
	cases := map[string]HSIPClass{
		"10.0.0.1":       HSIPPrivate,
		"192.168.1.1":    HSIPPrivate,
		"172.16.0.1":     HSIPPrivate,
		"172.31.255.255": HSIPPrivate,
		"100.64.0.1":     HSIPPrivate,
	}
	for ip, want := range cases {
		if got := HSClassifyIP4(ip); got != want {
			t.Fatalf("%s want %d got %d", ip, want, got)
		}
	}
}

func TestHSClassifyPublic(t *testing.T) {
	if HSClassifyIP4("52.84.12.9") != HSIPPublic {
		t.Fatal("public ip misclassified")
	}
	if HSClassifyIP4("172.32.0.1") != HSIPPublic {
		t.Fatal("172.32 is public (outside 16-31)")
	}
}

func TestHSClassifyLinkLocal(t *testing.T) {
	if HSClassifyIP4("169.254.169.254") != HSIPLinkLocal {
		t.Fatal("cloud metadata 169.254 should be link-local")
	}
}

func TestHSClassifyInvalid(t *testing.T) {
	bad := []string{"", "abc", "1.2.3", "1.2.3.4.5", "256.1.1.1", "224.0.0.1", "0.0.0.0"}
	for _, ip := range bad {
		if HSClassifyIP4(ip) != HSIPInvalid {
			t.Fatalf("%q should be invalid", ip)
		}
	}
}

func TestHSTrustedHostToLoopback(t *testing.T) {
	_, fs := HSAuditResolution("api.minecraftservices.com",
		[]string{"127.0.0.1"}, true)
	if !HSHasReason(fs, HSReasonTrustedHostToLoopback) {
		t.Fatalf("want loopback override: %v", fs)
	}
}

func TestHSTrustedHostToPrivate(t *testing.T) {
	_, fs := HSAuditResolution("sessionserver.example",
		[]string{"192.168.1.10"}, true)
	if !HSHasReason(fs, HSReasonTrustedHostToPrivate) {
		t.Fatalf("want private override: %v", fs)
	}
}

func TestHSMixedScopeRecords(t *testing.T) {
	_, fs := HSAuditResolution("api.example",
		[]string{"52.84.1.1", "10.0.0.9"}, true)
	if !HSHasReason(fs, HSReasonMixedScopeRecords) {
		t.Fatalf("want mixed scope: %v", fs)
	}
}

func TestHSPublicOnlyOK(t *testing.T) {
	safe, fs := HSAuditResolution("api.example",
		[]string{"52.84.1.1", "3.9.2.1"}, true)
	if !safe {
		t.Fatalf("public-only should be safe: %v", fs)
	}
}

func TestHSHostsOverride(t *testing.T) {
	lines := []string{
		"# localhost",
		"127.0.0.1 localhost",
		"10.0.0.66 api.minecraftservices.com  # hijack",
	}
	trusted := map[string]bool{"api.minecraftservices.com": true}
	fs := HSAuditHostsLines(lines, trusted)
	if !HSHasReason(fs, HSReasonHostsOverride) {
		t.Fatalf("want hosts override: %v", fs)
	}
}

func TestHSHostsCommentIgnored(t *testing.T) {
	lines := []string{"# 52.1.1.1 api.minecraftservices.com"}
	trusted := map[string]bool{"api.minecraftservices.com": true}
	if fs := HSAuditHostsLines(lines, trusted); len(fs) != 0 {
		t.Fatalf("commented hosts line must be ignored: %v", fs)
	}
}

func TestHSBaselineDrift(t *testing.T) {
	base, ok := HSBuildBaseline("52.84.10.1")
	if !ok {
		t.Fatal("baseline build failed")
	}
	if !HSDetectDrift(base, "203.0.113.5") {
		t.Fatal("different /16 should be drift")
	}
	if HSDetectDrift(base, "52.84.99.7") {
		t.Fatal("same /16 should not be drift")
	}
}

func TestHSBaselineInvalid(t *testing.T) {
	if _, ok := HSBuildBaseline("not-an-ip"); ok {
		t.Fatal("invalid ip cannot build baseline")
	}
}

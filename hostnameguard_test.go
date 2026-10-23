package main

import "testing"

func hngHasReason(fs []HNGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestHNGPublicDomain(t *testing.T) {
	pol := DefaultHNGPolicy()
	for _, a := range []string{"play.example.com", "mc.server.net:25565", "hypixel.net"} {
		if f := HNGEvaluate(a, pol); len(f) != 0 {
			t.Fatalf("public server %q must pass: %v", a, f)
		}
	}
}

func TestHNGPrivateIP(t *testing.T) {
	pol := DefaultHNGPolicy()
	for _, a := range []string{"127.0.0.1", "10.0.0.9:25565", "192.168.1.10", "169.254.169.254"} {
		f := HNGEvaluate(a, pol)
		if len(f) == 0 {
			t.Fatalf("private target %q must be flagged", a)
		}
	}
	if f := HNGEvaluate("169.254.169.254", pol); !hngHasReason(f, HNGReasonMetadataIP) {
		t.Fatal("metadata IP must be flagged as metadata")
	}
}

func TestHNGUnspecified(t *testing.T) {
	pol := DefaultHNGPolicy()
	if f := HNGEvaluate("0.0.0.0", pol); !hngHasReason(f, HNGReasonUnspecifiedIP) {
		t.Fatal("0.0.0.0 must be flagged")
	}
	if f := HNGEvaluate("[::]", pol); !hngHasReason(f, HNGReasonUnspecifiedIP) {
		t.Fatal("[::] must be flagged")
	}
}

func TestHNGIPv4MappedV6(t *testing.T) {
	pol := DefaultHNGPolicy()
	// ::ffff:127.0.0.1
	if f := HNGEvaluate("[::ffff:7f00:1]:25565", pol); !hngHasReason(f, HNGReasonMappedV4Loopback) {
		t.Fatal("ipv4-mapped loopback must be flagged")
	}
}

func TestHNGBadPort(t *testing.T) {
	pol := DefaultHNGPolicy()
	for _, a := range []string{"mc.net:0", "mc.net:70000", "mc.net:abc", "mc.net:0255"} {
		if f := HNGEvaluate(a, pol); !hngHasReason(f, HNGReasonBadPort) {
			t.Fatalf("bad port in %q must be flagged", a)
		}
	}
}

func TestHNGIPv6Bracket(t *testing.T) {
	pol := DefaultHNGPolicy()
	if f := HNGEvaluate("[2001:db8::1]:25565", pol); len(f) != 0 {
		t.Fatalf("public bracketed ipv6 with port must pass: %v", f)
	}
	if f := HNGEvaluate("[::1]:25565", pol); !hngHasReason(f, HNGReasonPrivateIP) {
		t.Fatal("[::1] loopback must be flagged")
	}
}

func TestHNGLongLabel(t *testing.T) {
	pol := DefaultHNGPolicy()
	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	if f := HNGEvaluate(long+".com", pol); !hngHasReason(f, HNGReasonLabelTooLong) {
		t.Fatal("64-char label must be flagged")
	}
}

func TestHNGIllegalChar(t *testing.T) {
	pol := DefaultHNGPolicy()
	if f := HNGEvaluate("mc server.com", pol); !hngHasReason(f, HNGReasonIllegalChar) {
		t.Fatal("space in hostname must be flagged")
	}
}

func TestHNGIntegerIP(t *testing.T) {
	pol := DefaultHNGPolicy()
	if f := HNGEvaluate("2130706433", pol); len(f) == 0 {
		t.Fatal("decimal integer IP must be flagged")
	}
}

func TestHNGEmpty(t *testing.T) {
	pol := DefaultHNGPolicy()
	if f := HNGEvaluate("", pol); !hngHasReason(f, HNGReasonEmptyHost) {
		t.Fatal("empty address must be flagged")
	}
}

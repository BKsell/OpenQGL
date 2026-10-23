package main

import "testing"

func TestJAHealthyRS256(t *testing.T) {
	if safe, _ := JAAudit(JAHeader{Alg: "RS256"}, JAKindRSA, 0); !safe {
		t.Fatal("RS256 verified as RSA should pass")
	}
}

func TestJAAlgNone(t *testing.T) {
	_, fs := JAAudit(JAHeader{Alg: "none"}, JAKindRSA, 0)
	if !JAHasReason(fs, JAReasonAlgNone) {
		t.Fatalf("alg none must be rejected: %v", fs)
	}
}

func TestJAAlgNoneCaseConfusion(t *testing.T) {
	_, fs := JAAudit(JAHeader{Alg: "NoNe"}, JAKindRSA, 0)
	if !JAHasReason(fs, JAReasonAlgNone) {
		t.Fatalf("case-muddled none must still reject: %v", fs)
	}
}

func TestJAHMACCryptoConfusion(t *testing.T) {
	// 验证方期望 RSA（用公钥），令牌却声称 HS256 → 公钥被当 HMAC 密钥
	_, fs := JAAudit(JAHeader{Alg: "HS256"}, JAKindRSA, 64)
	if !JAHasReason(fs, JAReasonAlgMismatch) {
		t.Fatalf("RS->HS confusion must flag: %v", fs)
	}
}

func TestJAWeakHMACKey(t *testing.T) {
	_, fs := JAAudit(JAHeader{Alg: "HS256"}, JAKindHMAC, 16)
	if !JAHasReason(fs, JAReasonWeakHMACKey) {
		t.Fatalf("short HMAC key must flag: %v", fs)
	}
}

func TestJAStrongHMACOK(t *testing.T) {
	if safe, _ := JAAudit(JAHeader{Alg: "HS256"}, JAKindHMAC, 32); !safe {
		t.Fatal("32-byte HMAC key acceptable")
	}
}

func TestJAUnknownAlg(t *testing.T) {
	_, fs := JAAudit(JAHeader{Alg: "XY999"}, JAKindRSA, 0)
	if !JAHasReason(fs, JAReasonAlgUnknown) {
		t.Fatalf("unknown alg must reject: %v", fs)
	}
}

func TestJAKidTraversal(t *testing.T) {
	_, fs := JAAudit(JAHeader{Alg: "RS256", Kid: "../../etc/keys/pem"},
		JAKindRSA, 0)
	if !JAHasReason(fs, JAReasonKidTraversal) {
		t.Fatalf("kid path traversal must flag: %v", fs)
	}
}

func TestJASegmentsHealthy(t *testing.T) {
	if safe, _ := JACheckSegments("a.b.c"); !safe {
		t.Fatal("three-segment token shape ok")
	}
}

func TestJASegmentsEmptySignature(t *testing.T) {
	_, fs := JACheckSegments("a.b.")
	if !JAHasReason(fs, JAReasonAlgNone) {
		t.Fatalf("empty signature segment implies unsigned: %v", fs)
	}
}

func TestJASegmentsMalformed(t *testing.T) {
	if safe, _ := JACheckSegments("only.two"); safe {
		t.Fatal("two segments must be malformed")
	}
	if safe, _ := JACheckSegments(""); safe {
		t.Fatal("empty token must be malformed")
	}
}

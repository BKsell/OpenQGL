package main

import "testing"

func pkceHas(fs []PKCEFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPKCEGoodVerifier(t *testing.T) {
	pol := DefaultPKCEPolicy()
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	safe, _ := PKCEValidateVerifier(v, pol)
	if !safe {
		t.Fatal("RFC example verifier should pass")
	}
}

func TestPKCEShortVerifier(t *testing.T) {
	pol := DefaultPKCEPolicy()
	_, fs := PKCEValidateVerifier("abc", pol)
	if !pkceHas(fs, PKCEReasonVerifierTooShort) {
		t.Fatalf("want short, got %v", fs)
	}
}

func TestPKCEBadCharset(t *testing.T) {
	pol := DefaultPKCEPolicy()
	bad := "bad verifier with spaces!!" + repeatPKCE("a", 30)
	_, fs := PKCEValidateVerifier(bad, pol)
	if !pkceHas(fs, PKCEReasonVerifierCharset) {
		t.Fatalf("want charset, got %v", fs)
	}
}

func TestPKCES256Matches(t *testing.T) {
	pol := DefaultPKCEPolicy()
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// RFC7636 附录 B 的期望值
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	got := PKCES256Challenge(v)
	if got != want {
		t.Fatalf("s256 mismatch\n got=%s\nwant=%s", got, want)
	}
	safe, _ := PKCEValidateChallenge("S256", got, got, pol)
	if !safe {
		t.Fatal("valid s256 challenge should pass")
	}
}

func TestPKCEPlainRejected(t *testing.T) {
	pol := DefaultPKCEPolicy()
	_, fs := PKCEValidateChallenge("plain", "dBjft..", "", pol)
	if !pkceHas(fs, PKCEReasonPlainMethod) {
		t.Fatalf("want plain reject, got %v", fs)
	}
}

func TestPKCEChallengeMismatch(t *testing.T) {
	pol := DefaultPKCEPolicy()
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	good := PKCES256Challenge(v)
	bad := repeatPKCE("A", 43)
	_, fs := PKCEValidateChallenge("S256", bad, good, pol)
	if !pkceHas(fs, PKCEReasonChallengeMismatch) {
		t.Fatalf("want mismatch, got %v", fs)
	}
}

func TestPKCEChallengeBadLen(t *testing.T) {
	pol := DefaultPKCEPolicy()
	_, fs := PKCEValidateChallenge("S256", "short", "", pol)
	if !pkceHas(fs, PKCEReasonChallengeBadLen) {
		t.Fatalf("want bad len, got %v", fs)
	}
}

func TestPKCEStateGood(t *testing.T) {
	pol := DefaultPKCEPolicy()
	s := "x9Q2kZ7mP4rT6vW8yA1bC3dE5fG0hJ"
	safe, _ := PKCEValidateState(s, pol)
	if !safe {
		t.Fatal("strong state should pass")
	}
}

func TestPKCEStateShort(t *testing.T) {
	pol := DefaultPKCEPolicy()
	_, fs := PKCEValidateState("abc", pol)
	if !pkceHas(fs, PKCEReasonStateTooShort) {
		t.Fatalf("want short state, got %v", fs)
	}
}

func TestPKCEStatePredictable(t *testing.T) {
	pol := DefaultPKCEPolicy()
	_, fs := PKCEValidateState("12345678901234567890", pol)
	if !pkceHas(fs, PKCEReasonStatePredictable) {
		t.Fatalf("want predictable numeric state, got %v", fs)
	}
}

func repeatPKCE(s string, n int) string {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, s[0])
	}
	return string(out)
}

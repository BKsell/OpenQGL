package main

import "testing"

func jwksHas(fs []JWTSFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestJWTSAlgNoneRejected(t *testing.T) {
	pol := DefaultJWTSPolicy()
	safe, fs := JWTSValidateHeader("none", "", pol)
	if safe || !jwksHas(fs, JWKSReasonAlgNone) {
		t.Fatalf("want alg none reject, got %v", fs)
	}
}

func TestJWTSAlgMissing(t *testing.T) {
	pol := DefaultJWTSPolicy()
	_, fs := JWTSValidateHeader("", "", pol)
	if !jwksHas(fs, JWKSReasonAlgMissing) {
		t.Fatalf("want alg missing, got %v", fs)
	}
}

func TestJWTSUnsupportedAlg(t *testing.T) {
	pol := DefaultJWTSPolicy()
	_, fs := JWTSValidateHeader("HS512", "", pol)
	if !jwksHas(fs, JWKSReasonUnsupportedAlg) {
		t.Fatalf("want unsupported alg, got %v", fs)
	}
}

func TestJWTSRS256GoodKid(t *testing.T) {
	pol := DefaultJWTSPolicy()
	safe, _ := JWTSValidateHeader("RS256", "2024-04-key-01", pol)
	if !safe {
		t.Fatal("valid alg + kid should pass")
	}
}

func TestJWTSKidPathTraversal(t *testing.T) {
	pol := DefaultJWTSPolicy()
	_, fs := JWTSValidateHeader("RS256", "../../etc/key", pol)
	if !jwksHas(fs, JWKSReasonKidUnsafe) {
		t.Fatalf("want unsafe kid, got %v", fs)
	}
}

func TestJWTSKidEmpty(t *testing.T) {
	pol := DefaultJWTSPolicy()
	_, fs := JWTSValidateHeader("ES256", "", pol)
	if !jwksHas(fs, JWKSReasonKidUnsafe) {
		t.Fatalf("want empty kid reject, got %v", fs)
	}
}

func TestJWTSClaimsGood(t *testing.T) {
	pol := DefaultJWTSPolicy()
	pol.NowUnix = 1000
	pol.ExpectedIssuer = "https://issuer.test"
	pol.ExpectedAudiences = []string{"launcher"}
	safe, _ := JWTSValidateClaims("https://issuer.test", []string{"launcher"}, 2000, 0, true, pol)
	if !safe {
		t.Fatal("valid claims should pass")
	}
}

func TestJWTSExpired(t *testing.T) {
	pol := DefaultJWTSPolicy()
	pol.NowUnix = 5000
	_, fs := JWTSValidateClaims("", nil, 1000, 0, true, pol)
	if !jwksHas(fs, JWKSReasonExpired) {
		t.Fatalf("want expired, got %v", fs)
	}
}

func TestJWTSMissingExp(t *testing.T) {
	pol := DefaultJWTSPolicy()
	_, fs := JWTSValidateClaims("", nil, 0, 0, false, pol)
	if !jwksHas(fs, JWKSReasonMissingExp) {
		t.Fatalf("want missing exp, got %v", fs)
	}
}

func TestJWTSNbfFuture(t *testing.T) {
	pol := DefaultJWTSPolicy()
	pol.NowUnix = 1000
	_, fs := JWTSValidateClaims("", nil, 2000, 9000, true, pol)
	if !jwksHas(fs, JWKSReasonNotBeforeFuture) {
		t.Fatalf("want nbf future, got %v", fs)
	}
}

func TestJWTSIssuerMismatch(t *testing.T) {
	pol := DefaultJWTSPolicy()
	pol.ExpectedIssuer = "https://issuer.test"
	_, fs := JWTSValidateClaims("https://evil.test", nil, 0, 0, false, pol)
	if !jwksHas(fs, JWKSReasonIssuerMismatch) {
		t.Fatalf("want issuer mismatch, got %v", fs)
	}
}

func TestJWTSAudienceMissing(t *testing.T) {
	pol := DefaultJWTSPolicy()
	pol.ExpectedAudiences = []string{"launcher"}
	_, fs := JWTSValidateClaims("", []string{"other"}, 0, 0, false, pol)
	if !jwksHas(fs, JWKSReasonAudienceMissing) {
		t.Fatalf("want audience missing, got %v", fs)
	}
}

func TestJWTSWeakHMAC(t *testing.T) {
	pol := DefaultJWTSPolicy()
	_, fs := JWKSValidateHMACSecret("short", pol)
	if !jwksHas(fs, JWKSReasonWeakHMACSecret) {
		t.Fatalf("want weak hmac, got %v", fs)
	}
}

func TestJWTSRSAKeyMaterial(t *testing.T) {
	safe, _ := JWKSValidateKeyMaterial("RSA", "nval", "AQAB", "", "", "")
	if !safe {
		t.Fatal("rsa with n,e should pass")
	}
	_, fs := JWKSValidateKeyMaterial("RSA", "", "", "", "", "")
	if !jwksHas(fs, JWKSReasonJWKMissingMaterial) {
		t.Fatal("rsa without material must fail")
	}
}

func TestJWTSECKeyMaterial(t *testing.T) {
	safe, _ := JWKSValidateKeyMaterial("EC", "", "", "P-256", "x", "y")
	if !safe {
		t.Fatal("ec with crv,x,y should pass")
	}
}

func TestJWTSOctInPublicJWKS(t *testing.T) {
	_, fs := JWKSValidateKeyMaterial("oct", "", "", "", "", "")
	if !jwksHas(fs, JWKSReasonJWKWeakKty) {
		t.Fatal("symmetric key must not appear in public jwks")
	}
}

func TestJWTSSegmentsStructure(t *testing.T) {
	if _, ok := jwtsSegments("aaa.bbb.ccc"); !ok {
		t.Fatal("valid compact jwt should have 3 segments")
	}
	if _, ok := jwtsSegments("aaa.bbb"); ok {
		t.Fatal("2 segments should fail")
	}
	if _, ok := jwtsSegments("aaa..ccc"); ok {
		t.Fatal("empty segment should fail")
	}
}

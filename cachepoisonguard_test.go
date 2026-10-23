package main

import "testing"

func TestCP2Healthy(t *testing.T) {
	r := CP2Response{
		Status:          200,
		VaryHeaders:     []string{"accept-encoding"},
		KeyInputs:       []string{"host", "scheme", "accept-encoding"},
		CacheDirectives: []string{"max-age=60"},
	}
	if safe, _ := CP2Audit(r); !safe {
		t.Fatal("well-keyed public cache should pass")
	}
}

func TestCP2VaryMismatch(t *testing.T) {
	r := CP2Response{
		Status:      200,
		VaryHeaders: []string{"accept-encoding"},
		KeyInputs:   []string{"x-forwarded-host"},
	}
	_, fs := CP2Audit(r)
	if !CP2HasReason(fs, CP2ReasonVaryMismatch) {
		t.Fatalf("unkeyed x-forwarded-host must flag: %v", fs)
	}
}

func TestCP2ReflectedUnkeyed(t *testing.T) {
	r := CP2Response{
		Status:          302,
		LocationHeader:  "https://evil/next",
		ReflectedHeader: "x-forwarded-host",
	}
	_, fs := CP2Audit(r)
	if !CP2HasReason(fs, CP2ReasonUnkeyedHeaderReflected) {
		t.Fatalf("reflected unkeyed header must flag: %v", fs)
	}
}

func TestCP2SharedWithAuth(t *testing.T) {
	r := CP2Response{
		Status:          200,
		HasAuthRequest:  true,
		CacheDirectives: []string{"public", "max-age=60"},
	}
	_, fs := CP2Audit(r)
	if !CP2HasReason(fs, CP2ReasonSharedWithAuth) {
		t.Fatalf("authorized response shared-cacheable must flag: %v", fs)
	}
}

func TestCP2PrivateAuthOK(t *testing.T) {
	r := CP2Response{
		Status:          200,
		HasAuthRequest:  true,
		CacheDirectives: []string{"private", "max-age=10"},
	}
	if safe, _ := CP2Audit(r); !safe {
		t.Fatal("private authorized response should pass")
	}
}

func TestCP2LongRedirectCache(t *testing.T) {
	r := CP2Response{
		Status:          302,
		CacheDirectives: []string{"max-age=3600"},
	}
	_, fs := CP2Audit(r)
	if !CP2HasReason(fs, CP2ReasonRedirectCachedLong) {
		t.Fatalf("long-cached redirect must flag: %v", fs)
	}
}

func TestCP2UnauthorizedNoStoreRequired(t *testing.T) {
	r := CP2Response{Status: 401, CacheDirectives: []string{"max-age=10"}}
	_, fs := CP2Audit(r)
	if !CP2HasReason(fs, CP2ReasonUncacheableStatus) {
		t.Fatalf("401 without no-store must flag: %v", fs)
	}
}

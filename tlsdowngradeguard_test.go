package main

import "testing"

func tlsdgHas(fs []TLSDGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestTLSDGGood(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	safe, _ := TLSDGEvaluate(TLSDGView{ServerName: "api.minecraftservices.com", MinVersion: tlsdgTLS12}, pol)
	if !safe {
		t.Fatal("tls1.2 should pass")
	}
}

func TestTLSDGSkipVerify(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{InsecureSkipVerify: true, MinVersion: tlsdgTLS12}, pol)
	if !tlsdgHas(fs, TLSDGReasonSkipVerify) {
		t.Fatalf("want skip verify, got %v", fs)
	}
}

func TestTLSDGGlobalBypass(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{InsecureSkipVerify: true, MinVersion: tlsdgTLS13}, pol)
	if !tlsdgHas(fs, TLSDGReasonBypassTooBroad) {
		t.Fatalf("want global bypass, got %v", fs)
	}
}

func TestTLSDGScopedSkipAllowed(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	pol.AllowScopedSkipVerify = true
	safe, _ := TLSDGEvaluate(TLSDGView{
		InsecureSkipVerify: true,
		MinVersion:         tlsdgTLS12,
		BypassScopeHosts:   []string{"legacy-skin.local"},
	}, pol)
	if !safe {
		t.Fatal("scoped skip should be allowed")
	}
}

func TestTLSDGTLS10(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{MinVersion: tlsdgTLS10}, pol)
	if !tlsdgHas(fs, TLSDGReasonMinVersionLow) {
		t.Fatalf("want low version, got %v", fs)
	}
}

func TestTLSDGMinUnset(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{}, pol)
	if !tlsdgHas(fs, TLSDGReasonMinVersionUnset) {
		t.Fatalf("want unset min, got %v", fs)
	}
}

func TestTLSDGWeakRC4(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{MinVersion: tlsdgTLS12, CipherSuites: []uint16{0x0005}}, pol)
	if !tlsdgHas(fs, TLSDGReasonWeakCipher) {
		t.Fatalf("want rc4 weak, got %v", fs)
	}
}

func TestTLSDGWeak3DES(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{MinVersion: tlsdgTLS12, CipherSuites: []uint16{0x000A}}, pol)
	if !tlsdgHas(fs, TLSDGReasonWeakCipher) {
		t.Fatalf("want 3des weak, got %v", fs)
	}
}

func TestTLSDGAnon(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{MinVersion: tlsdgTLS12, CipherSuites: []uint16{0x0034}}, pol)
	if !tlsdgHas(fs, TLSDGReasonNullAnonCipher) {
		t.Fatalf("want anon, got %v", fs)
	}
}

func TestTLSDGNullCipher(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{MinVersion: tlsdgTLS12, CipherSuites: []uint16{0x0001}}, pol)
	if !tlsdgHas(fs, TLSDGReasonNullAnonCipher) {
		t.Fatalf("want null, got %v", fs)
	}
}

func TestTLSDGHookNotEnforcing(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{
		MinVersion:             tlsdgTLS12,
		HasConnectionHook:      true,
		ConnectionHookEnforces: false,
	}, pol)
	if !tlsdgHas(fs, TLSDGReasonHookNotEnforcing) {
		t.Fatalf("want hook not enforcing, got %v", fs)
	}
}

func TestTLSDGMaxBelowMin(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{MinVersion: tlsdgTLS13, MaxVersion: tlsdgTLS12}, pol)
	if !tlsdgHas(fs, TLSDGReasonMaxBelowMin) {
		t.Fatalf("want max<min, got %v", fs)
	}
}

func TestTLSDGRenegotiation(t *testing.T) {
	pol := DefaultTLSDGPolicy()
	_, fs := TLSDGEvaluate(TLSDGView{MinVersion: tlsdgTLS12, RenegotiationFreely: true}, pol)
	if !tlsdgHas(fs, TLSDGReasonRenegotiationOpen) {
		t.Fatalf("want renegotiation, got %v", fs)
	}
}

func TestTLSDGCipherHexUnique(t *testing.T) {
	if tlsdgCipherHex(0x002F) != "0x002f" {
		t.Fatalf("hex wrong %s", tlsdgCipherHex(0x002F))
	}
}

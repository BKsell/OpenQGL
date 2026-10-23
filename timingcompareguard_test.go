package main

import "testing"

func TestTCEqual(t *testing.T) {
	if !TimingSafeEqual([]byte("secret-token"), []byte("secret-token")) {
		t.Fatal("equal values must compare true")
	}
	if TimingSafeEqualString("abc", "abd") {
		t.Fatal("differing strings must compare false")
	}
}

func TestTCDifferentLength(t *testing.T) {
	if TimingSafeEqual([]byte("abc"), []byte("abcd")) {
		t.Fatal("different lengths must be unequal")
	}
	if TimingSafeEqual(nil, []byte("x")) {
		t.Fatal("nil vs non-empty must be unequal")
	}
	if !TimingSafeEqual(nil, nil) {
		t.Fatal("two empty slices must be equal")
	}
}

func TestTCEmptyVsNonEmpty(t *testing.T) {
	// 多出的字节被 OR 入 diff，不能靠截断碰撞
	if TimingSafeEqual([]byte{}, []byte{0}) {
		t.Fatal("empty must not equal a zero byte")
	}
}

func TestTCSecretAuditRequiresConstantTime(t *testing.T) {
	if safe, _ := TCAuditCompare(false, TCKindSecret); safe {
		t.Fatal("secret compared early-exit must be flagged")
	}
	if safe, _ := TCAuditCompare(true, TCKindSecret); !safe {
		t.Fatal("secret compared constant-time should pass")
	}
}

func TestTCPublicMayEarlyExit(t *testing.T) {
	if safe, _ := TCAuditCompare(false, TCKindPublic); !safe {
		t.Fatal("non-secret comparison may use normal equality")
	}
}

func TestTCPrefixDoesNotCollide(t *testing.T) {
	if TimingSafeEqualString("token", "token-extra") {
		t.Fatal("prefix string must not collide with longer one")
	}
}

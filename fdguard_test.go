package main

import "testing"

func TestFDNoInheritance(t *testing.T) {
	tb := NewFDTable()
	tb.FDOpen(FDHandle{ID: "h1", Kind: FDKindTokenStore, Inheritable: false})
	tb.FDOpen(FDHandle{ID: "h2", Kind: FDKindFile, Inheritable: false})
	if safe, _ := tb.FDAuditSpawn(); !safe {
		t.Fatal("close-on-exec handles should not leak")
	}
}

func TestFDTokenLeak(t *testing.T) {
	tb := NewFDTable()
	tb.FDOpen(FDHandle{ID: "tok", Kind: FDKindTokenStore, Inheritable: true})
	_, fs := tb.FDAuditSpawn()
	if !FDHasFinding(fs, FDReasonSensitiveInherited) {
		t.Fatalf("inheritable token store must leak: %v", fs)
	}
}

func TestFDSocketLeak(t *testing.T) {
	tb := NewFDTable()
	tb.FDOpen(FDHandle{ID: "sock", Kind: FDKindListeningSocket, Inheritable: true})
	_, fs := tb.FDAuditSpawn()
	if !FDHasFinding(fs, FDReasonSocketInherited) {
		t.Fatalf("inheritable listening socket must leak: %v", fs)
	}
}

func TestFDPipeWriteLeak(t *testing.T) {
	tb := NewFDTable()
	tb.FDOpen(FDHandle{ID: "pw", Kind: FDKindPipeWrite, Inheritable: true})
	_, fs := tb.FDAuditSpawn()
	if !FDHasFinding(fs, FDReasonPipeWriteLeak) {
		t.Fatalf("inheritable pipe write end must leak: %v", fs)
	}
}

func TestFDClosedHandleNotLeaked(t *testing.T) {
	tb := NewFDTable()
	tb.FDOpen(FDHandle{ID: "tok", Kind: FDKindTokenStore, Inheritable: true})
	if ok, _ := tb.FDClose("tok"); !ok {
		t.Fatal("close should succeed")
	}
	if safe, _ := tb.FDAuditSpawn(); !safe {
		t.Fatal("closed handle should not be inherited")
	}
}

func TestFDDoubleClose(t *testing.T) {
	tb := NewFDTable()
	tb.FDOpen(FDHandle{ID: "h", Kind: FDKindFile})
	tb.FDClose("h")
	ok, reason := tb.FDClose("h")
	if ok || reason != FDReasonDoubleClose {
		t.Fatalf("double close must fail: ok=%v reason=%s", ok, reason)
	}
}

func TestFDCloseUnknown(t *testing.T) {
	tb := NewFDTable()
	ok, reason := tb.FDClose("ghost")
	if ok || reason != FDReasonCloseUnknown {
		t.Fatalf("close of untracked handle must fail: %s", reason)
	}
}

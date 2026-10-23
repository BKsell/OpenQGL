package main

import "testing"

func TestOSHealthyFlow(t *testing.T) {
	s := NewOSStore()
	state := "Ab3xY9zQw7kLm2nP"
	if ok, r := s.OSBegin(OSAttempt{State: state, SessionID: "sess1",
		RedirectURI: "https://app/cb"}); !ok {
		t.Fatalf("begin failed: %s", r)
	}
	if ok, _ := s.OSFinish(state, "sess1", "https://app/cb"); !ok {
		t.Fatal("matching callback should succeed")
	}
}

func TestOSMissingState(t *testing.T) {
	s := NewOSStore()
	if ok, fs := s.OSFinish("", "x", "y"); ok || len(fs) == 0 || fs[0] != OSReasonStateMissing {
		t.Fatalf("missing state must fail: %v", fs)
	}
}

func TestOSUnknownState(t *testing.T) {
	s := NewOSStore()
	ok, fs := s.OSFinish("never-issued-long-enough", "x", "y")
	if ok || fs[0] != OSReasonStateUnknown {
		t.Fatalf("unknown state must fail: %v", fs)
	}
}

func TestOSReplay(t *testing.T) {
	s := NewOSStore()
	state := "Zz8Yy7Xx6Ww5Vv4U"
	s.OSBegin(OSAttempt{State: state, SessionID: "a", RedirectURI: "u"})
	s.OSFinish(state, "a", "u")
	ok, fs := s.OSFinish(state, "a", "u")
	if ok || fs[0] != OSReasonStateReplay {
		t.Fatalf("replayed state must fail: %v", fs)
	}
}

func TestOSPredictable(t *testing.T) {
	s := NewOSStore()
	if ok, r := s.OSBegin(OSAttempt{State: "123"}); ok || r != OSReasonStatePredictable {
		t.Fatalf("short numeric state must be rejected: ok=%v r=%s", ok, r)
	}
	if ok, _ := s.OSBegin(OSAttempt{State: "aaaaaaaaaaaaaaaa"}); ok {
		t.Fatal("single-class state should be rejected")
	}
}

func TestOSSessionMismatch(t *testing.T) {
	s := NewOSStore()
	state := "Qq1Ww2Ee3Rr4Tt5Y"
	s.OSBegin(OSAttempt{State: state, SessionID: "victim", RedirectURI: "u"})
	ok, fs := s.OSFinish(state, "attacker", "u")
	if ok || fs[0] != OSReasonSessionMismatch {
		t.Fatalf("cross-session callback must fail: %v", fs)
	}
}

func TestOSRedirectMismatch(t *testing.T) {
	s := NewOSStore()
	state := "Aa1Ss2Dd3Ff4Gg5H"
	s.OSBegin(OSAttempt{State: state, SessionID: "a", RedirectURI: "https://app/cb"})
	ok, fs := s.OSFinish(state, "a", "https://evil/cb")
	if ok || fs[0] != OSReasonRedirectMismatch {
		t.Fatalf("redirect binding mismatch must fail: %v", fs)
	}
}

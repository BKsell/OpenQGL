package main

import "testing"

func ipcvTestPolicy() IPCVPolicy {
	return IPCVPolicy{
		MinVersion:     2,
		CurrentVersion: 4,
		AllowedOrigin:  "https://app.local",
		Methods: map[string]IPCVMethod{
			"openFile": {Name: "openFile", MinVersion: 2},
			"writeApp": {Name: "writeApp", MinVersion: 3},
			"oldCall":  {Name: "oldCall", MinVersion: 2, MaxVersion: 3, Deprecated: true},
		},
	}
}

func TestIPCVHealthySession(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	if ok, _ := s.Handshake(4); !ok {
		t.Fatal("handshake at current version should pass")
	}
	if ok, fs := s.HandleFrame(IPCVFrame{Method: "openFile", Nonce: "n1",
		Origin: "https://app.local"}); !ok {
		t.Fatalf("healthy frame should pass: %v", fs)
	}
}

func TestIPCVHandshakeTooOld(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	ok, fs := s.Handshake(1)
	if ok || !IPCVHas(fs, IPCVReasonVersionTooOld) {
		t.Fatalf("want version too old: ok=%v %v", ok, fs)
	}
}

func TestIPCVHandshakeTooNew(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	ok, fs := s.Handshake(9)
	if ok || !IPCVHas(fs, IPCVReasonVersionTooNew) {
		t.Fatalf("want future version: ok=%v %v", ok, fs)
	}
}

func TestIPCVFrameBeforeHandshake(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	ok, fs := s.HandleFrame(IPCVFrame{Method: "openFile", Nonce: "n", Origin: "https://app.local"})
	if ok || !IPCVHas(fs, IPCVReasonBeforeHandshake) {
		t.Fatalf("want before-handshake: ok=%v %v", ok, fs)
	}
}

func TestIPCVMethodRequiresHigherVersion(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	s.Handshake(2)
	ok, fs := s.HandleFrame(IPCVFrame{Method: "writeApp", Nonce: "n", Origin: "https://app.local"})
	if ok || !IPCVHas(fs, IPCVReasonVersionTooOld) {
		t.Fatalf("v2 should not call v3+ method: ok=%v %v", ok, fs)
	}
}

func TestIPCVMethodRemovedInVersion(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	s.Handshake(4)
	ok, fs := s.HandleFrame(IPCVFrame{Method: "oldCall", Nonce: "n", Origin: "https://app.local"})
	if ok {
		t.Fatalf("removed/deprecated method should not pass on v4: %v", fs)
	}
	if !IPCVHas(fs, IPCVReasonMethodNotInVersion) {
		t.Fatalf("want method unavailable: %v", fs)
	}
}

func TestIPCVDeprecatedWarningOnV3(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	s.Handshake(3)
	ok, _ := s.HandleFrame(IPCVFrame{Method: "oldCall", Nonce: "n", Origin: "https://app.local"})
	if ok {
		t.Fatal("deprecated method should still flag even when available")
	}
}

func TestIPCVOriginMismatch(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	s.Handshake(4)
	_, fs := s.HandleFrame(IPCVFrame{Method: "openFile", Nonce: "n",
		Origin: "https://evil.example"})
	if !IPCVHas(fs, IPCVReasonOriginMismatch) {
		t.Fatalf("want origin mismatch: %v", fs)
	}
}

func TestIPCVNonceReplay(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	s.Handshake(4)
	s.HandleFrame(IPCVFrame{Method: "openFile", Nonce: "dup", Origin: "https://app.local"})
	_, fs := s.HandleFrame(IPCVFrame{Method: "openFile", Nonce: "dup", Origin: "https://app.local"})
	if !IPCVHas(fs, IPCVReasonNonceReplay) {
		t.Fatalf("want nonce replay: %v", fs)
	}
}

func TestIPCVMissingNonce(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	s.Handshake(4)
	_, fs := s.HandleFrame(IPCVFrame{Method: "openFile", Nonce: "", Origin: "https://app.local"})
	if !IPCVHas(fs, IPCVReasonMissingNonce) {
		t.Fatalf("want missing nonce: %v", fs)
	}
}

func TestIPCVUnknownMethod(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	s.Handshake(4)
	_, fs := s.HandleFrame(IPCVFrame{Method: "arbitraryExec", Nonce: "n", Origin: "https://app.local"})
	if !IPCVHas(fs, IPCVReasonMethodNotInVersion) {
		t.Fatalf("want unknown method blocked: %v", fs)
	}
}

func TestIPCVVersionChangeMidSession(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	s.Handshake(4)
	ok, fs := s.RenegotiateVersion(2)
	if ok || !IPCVHas(fs, IPCVReasonVersionChanged) {
		t.Fatalf("mid-session downgrade must be rejected: ok=%v %v", ok, fs)
	}
}

func TestIPCVSameRenegotiateOK(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	s.Handshake(4)
	if ok, _ := s.RenegotiateVersion(4); !ok {
		t.Fatal("re-negotiating the same version should be allowed")
	}
}

func TestIPCVNegotiatedVersion(t *testing.T) {
	s := NewIPCVSession(ipcvTestPolicy())
	if s.NegotiatedVersion() != -1 {
		t.Fatal("before handshake version should be -1")
	}
	s.Handshake(3)
	if s.NegotiatedVersion() != 3 {
		t.Fatalf("negotiated version wrong %d", s.NegotiatedVersion())
	}
}

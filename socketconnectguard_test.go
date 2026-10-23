package main

import "testing"

func TestSCPortAllowed(t *testing.T) {
	allow := []int{80, 443}
	if !SCAllowedPort(443, allow) {
		t.Fatal("443 should be allowed")
	}
	for _, p := range []int{0, -1, 70000, 22} {
		if SCAllowedPort(p, allow) {
			t.Fatalf("port %d should be rejected", p)
		}
	}
}

func TestSCBlockedScope(t *testing.T) {
	if blocked, _ := SCBlockedScopeIP("127.0.0.1", false); !blocked {
		t.Fatal("loopback blocked")
	}
	if blocked, _ := SCBlockedScopeIP("169.254.169.254", false); !blocked {
		t.Fatal("metadata link-local blocked")
	}
	if blocked, _ := SCBlockedScopeIP("192.168.1.5", false); !blocked {
		t.Fatal("private blocked by default")
	}
	if blocked, _ := SCBlockedScopeIP("192.168.1.5", true); blocked {
		t.Fatal("private allowed when allowPrivate")
	}
	if blocked, _ := SCBlockedScopeIP("52.1.2.3", false); blocked {
		t.Fatal("public must be allowed")
	}
	if blocked, _ := SCBlockedScopeIP("0.0.0.0", false); !blocked {
		t.Fatal("0.0.0.0 unspecified blocked")
	}
}

func TestSCHealthyPinnedConnect(t *testing.T) {
	pin := SCPin{Host: "api.example", IP: "52.1.2.3", Port: 443,
		ValidTick: 100, TTL: 60}
	ok, fs := SCValidateConnect(pin, "api.example", "52.1.2.3", 443, 110,
		[]int{443}, false)
	if !ok {
		t.Fatalf("pinned connect should pass: %v", fs)
	}
}

func TestSCRebindingDifferentIP(t *testing.T) {
	pin := SCPin{Host: "api.example", IP: "52.1.2.3", Port: 443,
		ValidTick: 100, TTL: 60}
	// 第二次解析把地址换成内网
	ok, fs := SCValidateConnect(pin, "api.example", "10.0.0.5", 443, 110,
		[]int{443}, false)
	if ok {
		t.Fatalf("changed ip must fail: %v", fs)
	}
	if !SCHasReason(fs, SCReasonIPChanged) || !SCHasReason(fs, SCReasonBlockedScope) {
		t.Fatalf("want ip-changed and blocked-scope: %v", fs)
	}
}

func TestSCEmptyPin(t *testing.T) {
	ok, fs := SCValidateConnect(SCPin{}, "api.example", "52.1.2.3", 443, 1,
		[]int{443}, false)
	if ok || !SCHasReason(fs, SCReasonIPNotPinned) {
		t.Fatalf("empty pin must fail: ok=%v %v", ok, fs)
	}
}

func TestSCPinExpired(t *testing.T) {
	pin := SCPin{Host: "api.example", IP: "52.1.2.3", Port: 443,
		ValidTick: 100, TTL: 10}
	ok, fs := SCValidateConnect(pin, "api.example", "52.1.2.3", 443, 200,
		[]int{443}, false)
	if ok || !SCHasReason(fs, SCReasonPinExpired) {
		t.Fatalf("expired pin must fail: ok=%v %v", ok, fs)
	}
}

func TestSCPortMismatch(t *testing.T) {
	pin := SCPin{Host: "api.example", IP: "52.1.2.3", Port: 443,
		ValidTick: 1, TTL: 100}
	_, fs := SCValidateConnect(pin, "api.example", "52.1.2.3", 8080, 2,
		[]int{443}, false)
	if !SCHasReason(fs, SCReasonPortNotAllowed) {
		t.Fatalf("want port not allowed: %v", fs)
	}
}

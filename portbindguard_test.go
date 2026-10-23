package main

import "testing"

func pbgHas(fs []PBGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func pbgGood() PBGBindView {
	return PBGBindView{Host: "127.0.0.1", Port: 51234, IsLoopback: true,
		OneShot: true, HasStateCSRFGate: true}
}

func TestPBGGood(t *testing.T) {
	safe, _ := PBGEvaluate(pbgGood())
	if !safe {
		t.Fatal("loopback ephemeral one-shot with state should pass")
	}
}

func TestPBGIPv4Wildcard(t *testing.T) {
	v := pbgGood()
	v.Host = "0.0.0.0"
	_, fs := PBGEvaluate(v)
	if !pbgHas(fs, PBGReasonWildcardBind) {
		t.Fatalf("want wildcard, got %v", fs)
	}
}

func TestPBGIPv6Wildcard(t *testing.T) {
	v := pbgGood()
	v.Host = "::"
	_, fs := PBGEvaluate(v)
	if !pbgHas(fs, PBGReasonIPv6Wildcard) {
		t.Fatalf("want ipv6 wildcard, got %v", fs)
	}
}

func TestPBGExternalIP(t *testing.T) {
	v := pbgGood()
	v.Host = "192.168.1.20"
	v.IsLoopback = false
	_, fs := PBGEvaluate(v)
	if !pbgHas(fs, PBGReasonNonLoopbackBind) {
		t.Fatalf("want non-loopback, got %v", fs)
	}
}

func TestPBGLocalhostToken(t *testing.T) {
	v := pbgGood()
	v.Host = "localhost"
	safe, _ := PBGEvaluate(v)
	if !safe {
		t.Fatal("localhost token should pass")
	}
}

func TestPBGPrivilegedPort(t *testing.T) {
	v := pbgGood()
	v.Port = 80
	_, fs := PBGEvaluate(v)
	if !pbgHas(fs, PBGReasonPrivilegedPort) {
		t.Fatalf("want privileged port, got %v", fs)
	}
}

func TestPBGUPnP(t *testing.T) {
	v := pbgGood()
	v.UPnPPortForward = true
	_, fs := PBGEvaluate(v)
	if !pbgHas(fs, PBGReasonPortForwarding) {
		t.Fatalf("want upnp, got %v", fs)
	}
}

func TestPBGReuseAddr(t *testing.T) {
	v := pbgGood()
	v.SOReuseAddr = true
	_, fs := PBGEvaluate(v)
	if !pbgHas(fs, PBGReasonReuseAddr) {
		t.Fatalf("want reuseaddr, got %v", fs)
	}
}

func TestPBGNotOneShot(t *testing.T) {
	v := pbgGood()
	v.OneShot = false
	_, fs := PBGEvaluate(v)
	if !pbgHas(fs, PBGReasonPersistentServer) {
		t.Fatalf("want persistent, got %v", fs)
	}
}

func TestPBGMissingState(t *testing.T) {
	v := pbgGood()
	v.HasStateCSRFGate = false
	_, fs := PBGEvaluate(v)
	if !pbgHas(fs, PBGReasonMissingStateGate) {
		t.Fatalf("want missing state, got %v", fs)
	}
}

func TestPBGResolvedLoopbackFlag(t *testing.T) {
	v := pbgGood()
	v.Host = "127.0.0.2"
	safe, _ := PBGEvaluate(v)
	if !safe {
		t.Fatal("127/8 address is loopback and should pass")
	}
}

package main

import "testing"

func TestHBCleanHeaders(t *testing.T) {
	hs := []HBHeader{
		{Name: "Host", Value: "api.example"},
		{Name: "Authorization", Value: "Bearer x"},
		{Name: "Accept", Value: "application/json"},
	}
	if safe, _ := HBAuditForward(hs); !safe {
		t.Fatal("end-to-end headers should forward cleanly")
	}
}

func TestHBConnectionForwarded(t *testing.T) {
	hs := []HBHeader{{Name: "Connection", Value: "keep-alive"}}
	_, fs := HBAuditForward(hs)
	if !HBHasReason(fs, HBReasonHopByHopForwarded) {
		t.Fatalf("Connection must not be forwarded: %v", fs)
	}
}

func TestHBTransferEncodingForwarded(t *testing.T) {
	hs := []HBHeader{{Name: "Transfer-Encoding", Value: "chunked"}}
	_, fs := HBAuditForward(hs)
	if !HBHasReason(fs, HBReasonHopByHopForwarded) {
		t.Fatalf("TE must not be replayed: %v", fs)
	}
}

func TestHBProxyAuthReplayed(t *testing.T) {
	hs := []HBHeader{{Name: "Proxy-Authorization", Value: "Basic abc"}}
	_, fs := HBAuditForward(hs)
	if !HBHasReason(fs, HBReasonProxyAuthReplayed) {
		t.Fatalf("proxy-authorization replay must flag: %v", fs)
	}
}

func TestHBUpgradeReplayed(t *testing.T) {
	hs := []HBHeader{{Name: "Upgrade", Value: "h2c"}}
	_, fs := HBAuditForward(hs)
	if !HBHasReason(fs, HBReasonUpgradeReplayed) {
		t.Fatalf("upgrade replay must flag: %v", fs)
	}
}

func TestHBConnectionHidesHeader(t *testing.T) {
	hs := []HBHeader{
		{Name: "Connection", Value: "X-Internal-Token"},
		{Name: "X-Internal-Token", Value: "secret"},
	}
	_, fs := HBAuditForward(hs)
	if !HBHasReason(fs, HBReasonConnectionTokenHidesHeader) {
		t.Fatalf("connection-listed header manipulation must flag: %v", fs)
	}
}

func TestHBStrip(t *testing.T) {
	hs := []HBHeader{
		{Name: "Host", Value: "api.example"},
		{Name: "Keep-Alive", Value: "timeout=5"},
		{Name: "Accept", Value: "*/*"},
	}
	stripped := HBStripHopByHop(hs)
	if len(stripped) != 2 {
		t.Fatalf("strip should remove only keep-alive, got %d", len(stripped))
	}
	for _, h := range stripped {
		if hbLower(h.Name) == "keep-alive" {
			t.Fatal("keep-alive was not stripped")
		}
	}
}

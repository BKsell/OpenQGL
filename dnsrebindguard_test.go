package main

import "testing"

func TestDRPublicOnly(t *testing.T) {
	recs := []DRRecord{{IP: "52.84.1.9", TTL: 300}, {IP: "52.84.1.10", TTL: 300}}
	if safe, _ := DRAuditAnswerSet(recs); !safe {
		t.Fatal("all-public answer set should pass")
	}
}

func TestDRMixedScope(t *testing.T) {
	// 同一名字既给公网又给内网 —— rebinding 典型特征
	recs := []DRRecord{{IP: "52.84.1.9", TTL: 1}, {IP: "127.0.0.1", TTL: 1}}
	_, fs := DRAuditAnswerSet(recs)
	if !DRHasReason(fs, DRReasonMixedScopeRecords) {
		t.Fatalf("mixed scope records must flag: %v", fs)
	}
	if !DRHasReason(fs, DRReasonInternalRecord) {
		t.Fatalf("loopback record must flag: %v", fs)
	}
}

func TestDRLinkLocalMetadata(t *testing.T) {
	recs := []DRRecord{{IP: "169.254.169.254", TTL: 60}}
	_, fs := DRAuditAnswerSet(recs)
	if !DRHasReason(fs, DRReasonInternalRecord) {
		t.Fatalf("cloud metadata link-local must flag: %v", fs)
	}
}

func TestDRPrivate(t *testing.T) {
	recs := []DRRecord{{IP: "10.0.0.5", TTL: 60}}
	_, fs := DRAuditAnswerSet(recs)
	if !DRHasReason(fs, DRReasonInternalRecord) {
		t.Fatalf("private address in answer must flag: %v", fs)
	}
}

func TestDRSuspiciousTTL(t *testing.T) {
	recs := []DRRecord{{IP: "52.84.1.9", TTL: 0}, {IP: "192.168.0.1", TTL: 0}}
	_, fs := DRAuditAnswerSet(recs)
	if !DRHasReason(fs, DRReasonSuspiciousTTL) {
		t.Fatalf("zero TTL with mixed records must flag: %v", fs)
	}
}

func TestDRPinStable(t *testing.T) {
	if safe, _ := DRVerifyPin("52.84.1.9", "52.84.1.9"); !safe {
		t.Fatal("verify and connect addresses matching should pass")
	}
}

func TestDRPinDrift(t *testing.T) {
	// 校验时是公网，建连时被重绑定到环回
	_, fs := DRVerifyPin("52.84.1.9", "127.0.0.1")
	if !DRHasReason(fs, DRReasonPinDrift) {
		t.Fatalf("address drift between verify and connect must flag: %v", fs)
	}
}

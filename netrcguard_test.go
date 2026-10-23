package main

import "testing"

func nrcHasReason(fs []NRCFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestNRCClean(t *testing.T) {
	text := "machine maven.example.com login ci password a9f3kD28sLp01xzq\n"
	f := NRCScanText(text, 0o600)
	if len(f) != 0 {
		t.Fatalf("clean netrc entry must pass: %v", f)
	}
}

func TestNRCDefaultMachine(t *testing.T) {
	text := "default login anon password sometokenvalue123\n"
	f := NRCScanText(text, 0o600)
	if !nrcHasReason(f, NRCReasonDefaultMachine) {
		t.Fatal("default machine must be flagged")
	}
}

func TestNRCDuplicate(t *testing.T) {
	text := "machine a.example.com login u password longsecretvalue1\n" +
		"machine a.example.com login u2 password longsecretvalue2\n"
	f := NRCScanText(text, 0o600)
	if !nrcHasReason(f, NRCReasonDuplicateMachine) {
		t.Fatal("duplicate machine must be flagged")
	}
}

func TestNRCWeakAndEmpty(t *testing.T) {
	if f := NRCScanText("machine a.example.com login u password 123456\n", 0o600);
		!nrcHasReason(f, NRCReasonWeakPassword) {
		t.Fatal("placeholder password must be flagged")
	}
	if f := NRCScanText("machine a.example.com login u\n", 0o600);
		!nrcHasReason(f, NRCReasonEmptyPassword) {
		t.Fatal("missing password must be flagged")
	}
}

func TestNRCRawIP(t *testing.T) {
	f := NRCScanText("machine 10.0.0.9 login u password longsecretvalue1\n", 0o600)
	if !nrcHasReason(f, NRCReasonMachineIsIP) {
		t.Fatal("raw IP machine must be flagged")
	}
}

func TestNRCLocalhostNotBroad(t *testing.T) {
	f := NRCScanText("machine localhost login dev password longsecretvalue1\n", 0o600)
	if nrcHasReason(f, NRCReasonMachineTooBroad) {
		t.Fatal("localhost must not be treated as too broad")
	}
}

func TestNRCFileMode(t *testing.T) {
	if f := NRCScanText("machine a.example.com login u password longsecretvalue1\n", 0o644);
		!nrcHasReason(f, NRCReasonUnsafeFileMode) {
		t.Fatal("netrc world-readable mode must be flagged")
	}
}

func TestNRCMultiLineParse(t *testing.T) {
	text := "machine m.example.com\n  login ci\n  password longsecretvalue9\n"
	entries, errs := NRCParse(text)
	if len(errs) != 0 || len(entries) != 1 {
		t.Fatalf("multi-line entry parse wrong: %+v errs=%v", entries, errs)
	}
	if entries[0].Login != "ci" || entries[0].Password != "longsecretvalue9" {
		t.Fatalf("multi-line fields wrong: %+v", entries[0])
	}
}

package main

import "testing"

func fprHasReason(fs []FPRFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestFPRSecretSafe(t *testing.T) {
	pol := DefaultFPRPolicy()
	if f := FPREvaluate(FPREntry{Name: "account.json", Mode: 0o600, Class: FPRClassSecret}, pol); len(f) != 0 {
		t.Fatalf("0600 secret must pass: %v", f)
	}
}

func TestFPRSecretTooOpen(t *testing.T) {
	pol := DefaultFPRPolicy()
	f := FPREvaluate(FPREntry{Name: "token", Mode: 0o644, Class: FPRClassSecret}, pol)
	if !fprHasReason(f, FPRReasonBadSensitiveMode) ||
		!fprHasReason(f, FPRReasonGroupReadable) ||
		!fprHasReason(f, FPRReasonWorldReadable) {
		t.Fatalf("0644 secret must be flagged: %v", f)
	}
}

func TestFPRWorldWritable(t *testing.T) {
	pol := DefaultFPRPolicy()
	if f := FPREvaluate(FPREntry{Name: "cache.bin", Mode: 0o666, Class: FPRClassOrdinary}, pol);
		!fprHasReason(f, FPRReasonWorldWritable) {
		t.Fatal("0666 ordinary must be world-writable flagged")
	}
}

func TestFPRConfig(t *testing.T) {
	pol := DefaultFPRPolicy()
	if f := FPREvaluate(FPREntry{Name: "config.json", Mode: 0o640, Class: FPRClassConfig}, pol); len(f) != 0 {
		t.Fatalf("0640 config must pass: %v", f)
	}
	if f := FPREvaluate(FPREntry{Name: "config.json", Mode: 0o644, Class: FPRClassConfig}, pol);
		!fprHasReason(f, FPRReasonBadSensitiveMode) {
		t.Fatal("0644 config exceeds 0640 must be flagged")
	}
}

func TestFPRProgram(t *testing.T) {
	pol := DefaultFPRPolicy()
	if f := FPREvaluate(FPREntry{Name: "java.exe", Mode: 0o755, Class: FPRClassProgram}, pol); len(f) != 0 {
		t.Fatalf("0755 program must pass: %v", f)
	}
	if f := FPREvaluate(FPREntry{Name: "java.exe", Mode: 0o777, Class: FPRClassProgram}, pol);
		!fprHasReason(f, FPRReasonGroupWritable) && !fprHasReason(f, FPRReasonWorldWritable) {
		t.Fatal("0777 program must be flagged writable by non-owner")
	}
}

func TestFPRDirectory(t *testing.T) {
	pol := DefaultFPRPolicy()
	if f := FPREvaluate(FPREntry{Name: "secrets", Mode: 0o750, Class: FPRClassSecret, IsDir: true}, pol); len(f) != 0 {
		t.Fatalf("0750 secret dir must pass: %v", f)
	}
	if f := FPREvaluate(FPREntry{Name: "secrets", Mode: 0o777, Class: FPRClassSecret, IsDir: true}, pol);
		!fprHasReason(f, FPRReasonDirectoryTooOpen) {
		t.Fatal("0777 dir must be flagged")
	}
}

func TestFPRUnexpectedExecBit(t *testing.T) {
	pol := DefaultFPRPolicy()
	if f := FPREvaluate(FPREntry{Name: "notes.txt", Mode: 0o755, Class: FPRClassOrdinary}, pol);
		!fprHasReason(f, FPRReasonExecutableBitSet) {
		t.Fatal("execute bit on ordinary text must be flagged")
	}
}

func TestFPRSafeModeAndIsSafe(t *testing.T) {
	if FPRSafeModeFor(FPRClassSecret, false) != 0o600 {
		t.Fatal("secret file safe mode must be 0600")
	}
	if !FPRIsSafe(FPREntry{Name: "a", Mode: 0o644, Class: FPRClassOrdinary}) {
		t.Fatal("0644 ordinary must be safe")
	}
	if FPRIsSafe(FPREntry{Name: "t", Mode: 0o600 | 0o004, Class: FPRClassSecret}) {
		t.Fatal("secret with other-read must not be safe")
	}
}

package main

import "testing"

func TestLICleanValue(t *testing.T) {
	if safe, _ := LIAuditValue("player joined server.example"); !safe {
		t.Fatal("ordinary log value should be clean")
	}
}

func TestLICRLF(t *testing.T) {
	_, fs := LIAuditValue("name\nINFO auth ok")
	if !LIHasReason(fs, LIReasonCRLF) {
		t.Fatalf("embedded newline forges log line: %v", fs)
	}
}

func TestLICRLFCR(t *testing.T) {
	_, fs := LIAuditValue("evil\rfake")
	if !LIHasReason(fs, LIReasonCRLF) {
		t.Fatalf("carriage return must flag: %v", fs)
	}
}

func TestLINUL(t *testing.T) {
	_, fs := LIAuditValue("a\x00b")
	if !LIHasReason(fs, LIReasonNUL) {
		t.Fatalf("NUL byte must flag: %v", fs)
	}
}

func TestLIANSIEscape(t *testing.T) {
	_, fs := LIAuditValue("\x1b[2Jclear")
	if !LIHasReason(fs, LIReasonANSIEscape) {
		t.Fatalf("ANSI escape must flag: %v", fs)
	}
}

func TestLIControl(t *testing.T) {
	_, fs := LIAuditValue("a\x01b")
	if !LIHasReason(fs, LIReasonControl) {
		t.Fatalf("C0 control char must flag: %v", fs)
	}
}

func TestLISanitizeRemovesBreak(t *testing.T) {
	got := LISanitizeLog("a\nb\rc\x00d\x1b[1m")
	for i := 0; i < len(got); i++ {
		if got[i] == '\n' || got[i] == '\r' || got[i] == 0 || got[i] == 0x1b {
			t.Fatalf("sanitized text still dangerous at %d: %q", i, got)
		}
	}
	if safe, _ := LIAuditValue(got); !safe {
		t.Fatalf("sanitized output should re-audit clean: %q", got)
	}
}

func TestLISanitizeKeepsReadable(t *testing.T) {
	if got := LISanitizeLog("server_1"); got != "server_1" {
		t.Fatalf("readable text must be preserved, got %q", got)
	}
}

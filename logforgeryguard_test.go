package main

import "testing"

func lfgHasReason(fs []LFGFinding, reason string) bool {
	for _, f := range fs {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestLFGBasicLineBreak(t *testing.T) {
	pol := DefaultLFGPolicy()
	if f := LFGScan("hello\nworld", pol); !lfgHasReason(f, LFGReasonCRLF) {
		t.Fatal("LF must be flagged")
	}
	if f := LFGScan("a\rb", pol); !lfgHasReason(f, LFGReasonCarriage) {
		t.Fatal("CR must be flagged")
	}
}

func TestLFGForgedLine(t *testing.T) {
	pol := DefaultLFGPolicy()
	evil := "[ERROR] token=abcd\n"
	f := LFGScan(evil, pol)
	if !lfgHasReason(f, LFGReasonForgedLevel) || !lfgHasReason(f, LFGReasonCRLF) {
		t.Fatalf("forged level + newline must both flag: %v", f)
	}
}

func TestLFGANSIEscape(t *testing.T) {
	pol := DefaultLFGPolicy()
	evil := "good\x1b[2Jcleared"
	if f := LFGScan(evil, pol); !lfgHasReason(f, LFGReasonANSI) {
		t.Fatal("ANSI clear sequence must be flagged")
	}
}

func TestLFGUnicodeSeparators(t *testing.T) {
	pol := DefaultLFGPolicy()
	if f := LFGScan("line1\u2028line2", pol); !lfgHasReason(f, LFGReasonUnicodeLine) {
		t.Fatal("U+2028 must be flagged")
	}
	if f := LFGScan("line1\u0085x", pol); !lfgHasReason(f, LFGReasonUnicodeLine) {
		t.Fatal("NEL must be flagged")
	}
}

func TestLFGNullAndControl(t *testing.T) {
	pol := DefaultLFGPolicy()
	if f := LFGScan("a\x00b", pol); !lfgHasReason(f, LFGReasonNullByte) {
		t.Fatal("NUL must be flagged")
	}
	if f := LFGScan("a\x01b", pol); !lfgHasReason(f, LFGReasonControlChar) {
		t.Fatal("SOH must be flagged")
	}
}

func TestLFGCleanText(t *testing.T) {
	pol := DefaultLFGPolicy()
	clean := "Steve_玩家 1.20.4 normal-server"
	if f := LFGScan(clean, pol); len(f) != 0 {
		t.Fatalf("clean text must pass: %v", f)
	}
	// 普通以年份风格字符开头的昵称不应被误判。
	if f := LFGScan("2024player", pol); lfgHasReason(f, LFGReasonForgedLevel) {
		t.Fatal("2024player must not be treated as forged prefix")
	}
}

func TestLFGChineseNoFalsePositive(t *testing.T) {
	pol := DefaultLFGPolicy()
	if f := LFGScan("中文服务器名称，正常。", pol); len(f) != 0 {
		t.Fatalf("utf-8 text must pass: %v", f)
	}
}

func TestLFGSanitizeSingleLine(t *testing.T) {
	pol := DefaultLFGPolicy()
	safe := LFGSanitize("name\n[ERROR]\x1b[2J", pol)
	for i := 0; i < len(safe); i++ {
		if safe[i] == '\n' || safe[i] == '\r' || safe[i] == 0x1b {
			t.Fatal("sanitized output still contains dangerous byte")
		}
	}
	if LFGIsSafe("clean text 123") != true {
		t.Fatal("clean text must be safe")
	}
	if LFGIsSafe("a\nb") != false {
		t.Fatal("embedded newline must not be safe")
	}
}

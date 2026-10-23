package main

import "testing"

func TestCQExePathSpacedQuoted(t *testing.T) {
	if safe, _ := CQAuditExePath(`"C:\Program Files\Java\bin\javaw.exe"`); !safe {
		t.Fatal("quoted spaced exe path should pass")
	}
}

func TestCQExePathSpacedUnquoted(t *testing.T) {
	_, fs := CQAuditExePath(`C:\Program Files\Java\bin\javaw.exe`)
	if !CQHasReason(fs, CQReasonUnquotedSpace) {
		t.Fatalf("unquoted spaced exe path must flag: %v", fs)
	}
}

func TestCQExePathNoSpaceOK(t *testing.T) {
	if safe, _ := CQAuditExePath(`C:\Java\bin\javaw.exe`); !safe {
		t.Fatal("path without space needs no quotes")
	}
}

func TestCQQuoteSimple(t *testing.T) {
	if got := CQQuoteArgument("plain"); got != "plain" {
		t.Fatalf("simple arg should not be quoted: %q", got)
	}
}

func TestCQQuoteSpaced(t *testing.T) {
	got := CQQuoteArgument(`C:\Program Files\x`)
	if got != `"C:\Program Files\x"` {
		t.Fatalf("spaced arg quoting wrong: %q", got)
	}
}

func TestCQQuoteTrailingBackslash(t *testing.T) {
	// 结尾反斜杠在闭合引号前必须翻倍，否则会吃掉引号
	got := CQQuoteArgument(`C:\dir\`)
	if got != `"C:\dir\\"` {
		t.Fatalf("trailing backslash must be doubled: %q", got)
	}
}

func TestCQQuoteEmbeddedQuote(t *testing.T) {
	got := CQQuoteArgument(`a"b`)
	if got != `"a""b"` {
		t.Fatalf("embedded quote must be doubled: %q", got)
	}
}

func TestCQArgumentMetachar(t *testing.T) {
	_, fs := CQAuditArgument(`-Djava=x & calc`)
	if !CQHasReason(fs, CQReasonShellMetachar) {
		t.Fatalf("shell metacharacter in arg must flag: %v", fs)
	}
}

func TestCQArgumentUnescapedQuote(t *testing.T) {
	_, fs := CQAuditArgument(`-Dfoo=bar"baz`)
	if !CQHasReason(fs, CQReasonUnescapedQuote) {
		t.Fatalf("lone quote in arg must flag: %v", fs)
	}
}

func TestCQArgumentUnbalanced(t *testing.T) {
	_, fs := CQAuditArgument(`"C:\unbalanced`)
	if !CQHasReason(fs, CQReasonUnbalancedQuotes) {
		t.Fatalf("unbalanced quotes must flag: %v", fs)
	}
}

func TestCQRoundTripSafe(t *testing.T) {
	// 经 CQQuoteArgument 产出的串，对其去掉外层引号语义应无元字符注入面
	samples := []string{`C:\Program Files\Java`, `trail\`, `q"x`, "tab\there"}
	for _, s := range samples {
		q := CQQuoteArgument(s)
		// 引用后必须整体以成对引号包裹（需要引用的样本）
		if cqNeedsQuoting(s) && (q[0] != '"' || q[len(q)-1] != '"') {
			t.Fatalf("quoted sample not wrapped: %q -> %q", s, q)
		}
	}
}

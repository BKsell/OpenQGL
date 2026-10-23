package main

import "testing"

func TestPRBasic(t *testing.T) {
	r := PRParse("a=1\nb=2\n")
	if len(r.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(r.Entries))
	}
	if r.Entries[0].Key != "a" || r.Entries[0].Value != "1" {
		t.Fatalf("first entry wrong: %+v", r.Entries[0])
	}
	if PRHasReason(r, PRReasonDuplicateKey) {
		t.Fatal("distinct keys must not be duplicates")
	}
}

func TestPRComment(t *testing.T) {
	r := PRParse("# comment\n! bang\nk=v\n")
	if len(r.Entries) != 1 || r.Entries[0].Key != "k" {
		t.Fatalf("comments must be skipped: %+v", r.Entries)
	}
}

func TestPRContinuation(t *testing.T) {
	r := PRParse("a=one\\\n  two\n")
	if r.Entries[0].Value != "onetwo" {
		t.Fatalf("backslash continuation must join logical line, got %q", r.Entries[0].Value)
	}
}

func TestPRDuplicateKey(t *testing.T) {
	r := PRParse("k=1\nk=2\n")
	if !PRHasReason(r, PRReasonDuplicateKey) {
		t.Fatalf("duplicate key must flag last-wins ambiguity: %v", r.Findings)
	}
}

func TestPRMalformedUnicode(t *testing.T) {
	r := PRParse("a=\\u00zz\n")
	if !PRHasReason(r, PRReasonMalformedUnicode) {
		t.Fatalf("malformed \\u escape must flag: %v", r.Findings)
	}
}

func TestPRUnicodeNewlineInjection(t *testing.T) {
	// \u000a = LF，借 unicode 转义把换行注入值
	r := PRParse("a=x\\u000ay\n")
	if !PRHasReason(r, PRReasonBareControlInValue) {
		t.Fatalf("unicode-escaped LF in value must flag: %v", r.Findings)
	}
}

func TestPRStrayCR(t *testing.T) {
	r := PRParse("a=1\rb=2\r\n")
	if !PRHasReason(r, PRReasonStrayCR) {
		t.Fatalf("lone CR must flag inconsistent newline handling: %v", r.Findings)
	}
}

func TestPRDanglingContinue(t *testing.T) {
	r := PRParse("a=value\\")
	if !PRHasReason(r, PRReasonDanglingContinue) {
		t.Fatalf("trailing backslash at EOF must flag: %v", r.Findings)
	}
}

func TestPRKeyWhitespace(t *testing.T) {
	// 键内带转义空白（罕见且易错）
	r := PRParse("bad\\ key=v\n")
	if !PRHasReason(r, PRReasonKeyWhitespace) {
		t.Fatalf("embedded whitespace in key must flag: %v", r.Findings)
	}
}

func TestPREscapes(t *testing.T) {
	r := PRParse("a=\\t\\n\\r\n")
	if r.Entries[0].Value != "\t\n\r" {
		t.Fatalf("standard escapes wrong: %q", r.Entries[0].Value)
	}
}

package main

import "testing"

func TestINIBasic(t *testing.T) {
	r := INIParse("[java]\npath=C:\\jdk\nmem=2G\n")
	if len(r.Entries) != 2 {
		t.Fatalf("expected 2 entries got %d", len(r.Entries))
	}
	if r.Entries[0].Section != "java" || r.Entries[0].Key != "path" {
		t.Fatalf("section/key parse wrong: %+v", r.Entries[0])
	}
}

func TestINIComment(t *testing.T) {
	r := INIParse("; note\n# also note\nk=v\n")
	if len(r.Entries) != 1 {
		t.Fatalf("comments must be skipped, got %d", len(r.Entries))
	}
}

func TestINIDuplicateKey(t *testing.T) {
	r := INIParse("[s]\nk=1\nk=2\n")
	if !INIHasReason(r, INIReasonDuplicateKey) {
		t.Fatalf("duplicate key in section must flag: %v", r.Findings)
	}
}

func TestINIDuplicateAcrossSectionsOK(t *testing.T) {
	r := INIParse("[a]\nk=1\n[b]\nk=2\n")
	if INIHasReason(r, INIReasonDuplicateKey) {
		t.Fatal("same key in different sections is not a duplicate")
	}
}

func TestINIUnclosedSection(t *testing.T) {
	r := INIParse("[bad\nk=v\n")
	if !INIHasReason(r, INIReasonUnclosedSection) {
		t.Fatalf("unclosed section bracket must flag: %v", r.Findings)
	}
}

func TestINIMissingEquals(t *testing.T) {
	r := INIParse("garbage-line\n")
	if !INIHasReason(r, INIReasonMissingEquals) {
		t.Fatalf("line without = must flag: %v", r.Findings)
	}
}

func TestINIBOM(t *testing.T) {
	r := INIParse("\xef\xbb\xbfk=v\n")
	if !INIHasReason(r, INIReasonBOM) {
		t.Fatalf("UTF-8 BOM must flag: %v", r.Findings)
	}
}

func TestINIUnbalancedQuote(t *testing.T) {
	r := INIParse("k=\"unbalanced\n")
	if !INIHasReason(r, INIReasonUnbalancedQuote) {
		t.Fatalf("unbalanced quoted value must flag: %v", r.Findings)
	}
}

func TestINIBalancedQuoteStripped(t *testing.T) {
	r := INIParse("k=\"hello world\"\n")
	if r.Entries[0].Value != "hello world" {
		t.Fatalf("balanced quotes should be stripped, got %q", r.Entries[0].Value)
	}
}

func TestINIEmptySectionName(t *testing.T) {
	r := INIParse("[]\nk=v\n")
	if !INIHasReason(r, INIReasonEmptySectionName) {
		t.Fatalf("empty section name must flag: %v", r.Findings)
	}
}

func TestINICRLF(t *testing.T) {
	r := INIParse("[s]\r\nk=v\r\n")
	if len(r.Entries) != 1 || r.Entries[0].Value != "v" {
		t.Fatalf("CRLF lines must parse normally, got %+v", r.Entries)
	}
}

package main

import "testing"

func TestLDFBlockFlagged(t *testing.T) {
	for _, tok := range LDFBlock {
		in := tok
		r := LDFAudit(in)
		if !LDFHas(r, LDFReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestLDFWarnFlagged(t *testing.T) {
	for _, tok := range LDFWarn {
		r := LDFAudit(tok)
		if !LDFHas(r, LDFReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestLDFAllowSafe(t *testing.T) {
	for _, tok := range LDFAllow {
		r := LDFAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestLDFEmpty(t *testing.T) {
	if r := LDFAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestLDFSplit(t *testing.T) {
	toks := LDFSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

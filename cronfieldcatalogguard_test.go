package main

import "testing"

func TestCRNBlockFlagged(t *testing.T) {
	for _, tok := range CRNBlock {
		in := tok
		r := CRNAudit(in)
		if !CRNHas(r, CRNReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestCRNWarnFlagged(t *testing.T) {
	for _, tok := range CRNWarn {
		r := CRNAudit(tok)
		if !CRNHas(r, CRNReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestCRNAllowSafe(t *testing.T) {
	for _, tok := range CRNAllow {
		r := CRNAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestCRNEmpty(t *testing.T) {
	if r := CRNAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestCRNSplit(t *testing.T) {
	toks := CRNSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

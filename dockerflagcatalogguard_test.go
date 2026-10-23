package main

import "testing"

func TestDKFBlockFlagged(t *testing.T) {
	for _, tok := range DKFBlock {
		in := tok
		r := DKFAudit(in)
		if !DKFHas(r, DKFReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestDKFWarnFlagged(t *testing.T) {
	for _, tok := range DKFWarn {
		r := DKFAudit(tok)
		if !DKFHas(r, DKFReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestDKFAllowSafe(t *testing.T) {
	for _, tok := range DKFAllow {
		r := DKFAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestDKFEmpty(t *testing.T) {
	if r := DKFAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestDKFSplit(t *testing.T) {
	toks := DKFSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

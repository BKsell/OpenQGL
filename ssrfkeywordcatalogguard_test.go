package main

import "testing"

func TestSRFBlockFlagged(t *testing.T) {
	for _, tok := range SRFBlock {
		in := tok
		r := SRFAudit(in)
		if !SRFHas(r, SRFReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestSRFWarnFlagged(t *testing.T) {
	for _, tok := range SRFWarn {
		r := SRFAudit(tok)
		if !SRFHas(r, SRFReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestSRFAllowSafe(t *testing.T) {
	for _, tok := range SRFAllow {
		r := SRFAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestSRFEmpty(t *testing.T) {
	if r := SRFAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestSRFSplit(t *testing.T) {
	toks := SRFSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

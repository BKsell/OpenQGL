package main

import "testing"

func TestORPBlockFlagged(t *testing.T) {
	for _, tok := range ORPBlock {
		in := tok
		r := ORPAudit(in)
		if !ORPHas(r, ORPReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestORPWarnFlagged(t *testing.T) {
	for _, tok := range ORPWarn {
		r := ORPAudit(tok)
		if !ORPHas(r, ORPReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestORPAllowSafe(t *testing.T) {
	for _, tok := range ORPAllow {
		r := ORPAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestORPEmpty(t *testing.T) {
	if r := ORPAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestORPSplit(t *testing.T) {
	toks := ORPSplit("a,b,c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

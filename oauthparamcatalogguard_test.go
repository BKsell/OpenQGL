package main

import "testing"

func TestOPMBlockFlagged(t *testing.T) {
	for _, tok := range OPMBlock {
		in := tok
		r := OPMAudit(in)
		if !OPMHas(r, OPMReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestOPMWarnFlagged(t *testing.T) {
	for _, tok := range OPMWarn {
		r := OPMAudit(tok)
		if !OPMHas(r, OPMReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestOPMAllowSafe(t *testing.T) {
	for _, tok := range OPMAllow {
		r := OPMAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestOPMEmpty(t *testing.T) {
	if r := OPMAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestOPMSplit(t *testing.T) {
	toks := OPMSplit("a,b,c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

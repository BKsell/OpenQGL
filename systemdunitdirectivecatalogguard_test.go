package main

import "testing"

func TestSUDBlockFlagged(t *testing.T) {
	for _, tok := range SUDBlock {
		in := tok
		r := SUDAudit(in)
		if !SUDHas(r, SUDReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestSUDWarnFlagged(t *testing.T) {
	for _, tok := range SUDWarn {
		r := SUDAudit(tok)
		if !SUDHas(r, SUDReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestSUDAllowSafe(t *testing.T) {
	for _, tok := range SUDAllow {
		r := SUDAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestSUDEmpty(t *testing.T) {
	if r := SUDAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestSUDSplit(t *testing.T) {
	toks := SUDSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

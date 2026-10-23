package main

import "testing"

func TestEINBlockFlagged(t *testing.T) {
	for _, tok := range EINBlock {
		in := tok
		r := EINAudit(in)
		if !EINHas(r, EINReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestEINWarnFlagged(t *testing.T) {
	for _, tok := range EINWarn {
		r := EINAudit(tok)
		if !EINHas(r, EINReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestEINAllowSafe(t *testing.T) {
	for _, tok := range EINAllow {
		r := EINAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestEINEmpty(t *testing.T) {
	if r := EINAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestEINSplit(t *testing.T) {
	toks := EINSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

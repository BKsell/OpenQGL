package main

import "testing"

func TestMOCBlockFlagged(t *testing.T) {
	for _, tok := range MOCBlock {
		in := tok
		r := MOCAudit(in)
		if !MOCHas(r, MOCReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestMOCWarnFlagged(t *testing.T) {
	for _, tok := range MOCWarn {
		r := MOCAudit(tok)
		if !MOCHas(r, MOCReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestMOCAllowSafe(t *testing.T) {
	for _, tok := range MOCAllow {
		r := MOCAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestMOCEmpty(t *testing.T) {
	if r := MOCAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestMOCSplit(t *testing.T) {
	toks := MOCSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

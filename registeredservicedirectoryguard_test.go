package main

import "testing"

func TestRSDBlockFlagged(t *testing.T) {
	for _, tok := range RSDBlock {
		in := tok
		r := RSDAudit(in)
		if !RSDHas(r, RSDReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestRSDWarnFlagged(t *testing.T) {
	for _, tok := range RSDWarn {
		r := RSDAudit(tok)
		if !RSDHas(r, RSDReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestRSDAllowSafe(t *testing.T) {
	for _, tok := range RSDAllow {
		r := RSDAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestRSDEmpty(t *testing.T) {
	if r := RSDAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestRSDSplit(t *testing.T) {
	toks := RSDSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

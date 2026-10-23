package main

import "testing"

func TestRNDBlockFlagged(t *testing.T) {
	for _, tok := range RNDBlock {
		in := tok
		r := RNDAudit(in)
		if !RNDHas(r, RNDReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestRNDWarnFlagged(t *testing.T) {
	for _, tok := range RNDWarn {
		r := RNDAudit(tok)
		if !RNDHas(r, RNDReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestRNDAllowSafe(t *testing.T) {
	for _, tok := range RNDAllow {
		r := RNDAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestRNDEmpty(t *testing.T) {
	if r := RNDAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestRNDSplit(t *testing.T) {
	toks := RNDSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

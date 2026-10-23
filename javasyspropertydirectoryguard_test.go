package main

import "testing"

func TestJADBlockFlagged(t *testing.T) {
	for _, tok := range JADBlock {
		in := "-D" + tok + "=x"
		r := JADAudit(in)
		if !JADHas(r, JADReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestJADWarnFlagged(t *testing.T) {
	for _, tok := range JADWarn {
		r := JADAudit(tok)
		if !JADHas(r, JADReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestJADAllowSafe(t *testing.T) {
	for _, tok := range JADAllow {
		r := JADAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestJADEmpty(t *testing.T) {
	if r := JADAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestJADSplit(t *testing.T) {
	toks := JADSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

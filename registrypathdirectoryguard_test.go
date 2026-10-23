package main

import "testing"

func TestWRDBlockFlagged(t *testing.T) {
	for _, tok := range WRDBlock {
		in := tok
		r := WRDAudit(in)
		if !WRDHas(r, WRDReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestWRDWarnFlagged(t *testing.T) {
	for _, tok := range WRDWarn {
		r := WRDAudit(tok)
		if !WRDHas(r, WRDReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestWRDAllowSafe(t *testing.T) {
	for _, tok := range WRDAllow {
		r := WRDAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestWRDEmpty(t *testing.T) {
	if r := WRDAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestWRDSplit(t *testing.T) {
	toks := WRDSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

package main

import "testing"

func TestHFDBlockFlagged(t *testing.T) {
	for _, tok := range HFDBlock {
		in := tok
		r := HFDAudit(in)
		if !HFDHas(r, HFDReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestHFDWarnFlagged(t *testing.T) {
	for _, tok := range HFDWarn {
		r := HFDAudit(tok)
		if !HFDHas(r, HFDReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestHFDAllowSafe(t *testing.T) {
	for _, tok := range HFDAllow {
		r := HFDAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestHFDEmpty(t *testing.T) {
	if r := HFDAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestHFDSplit(t *testing.T) {
	toks := HFDSplit("a,b,c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

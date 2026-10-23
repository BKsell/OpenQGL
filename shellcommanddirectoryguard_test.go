package main

import "testing"

func TestCVDBlockFlagged(t *testing.T) {
	for _, tok := range CVDBlock {
		in := tok
		r := CVDAudit(in)
		if !CVDHas(r, CVDReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestCVDWarnFlagged(t *testing.T) {
	for _, tok := range CVDWarn {
		r := CVDAudit(tok)
		if !CVDHas(r, CVDReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestCVDAllowSafe(t *testing.T) {
	for _, tok := range CVDAllow {
		r := CVDAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestCVDEmpty(t *testing.T) {
	if r := CVDAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestCVDSplit(t *testing.T) {
	toks := CVDSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

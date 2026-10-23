package main

import "testing"

func TestPRDBlockFlagged(t *testing.T) {
	for _, tok := range PRDBlock {
		in := tok
		r := PRDAudit(in)
		if !PRDHas(r, PRDReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestPRDWarnFlagged(t *testing.T) {
	for _, tok := range PRDWarn {
		r := PRDAudit(tok)
		if !PRDHas(r, PRDReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestPRDAllowSafe(t *testing.T) {
	for _, tok := range PRDAllow {
		r := PRDAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestPRDEmpty(t *testing.T) {
	if r := PRDAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestPRDSplit(t *testing.T) {
	toks := PRDSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

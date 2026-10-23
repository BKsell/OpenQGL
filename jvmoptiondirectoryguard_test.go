package main

import "testing"

func TestJODBlockFlagged(t *testing.T) {
	for _, tok := range JODBlock {
		in := tok
		r := JODAudit(in)
		if !JODHas(r, JODReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestJODWarnFlagged(t *testing.T) {
	for _, tok := range JODWarn {
		r := JODAudit(tok)
		if !JODHas(r, JODReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestJODAllowSafe(t *testing.T) {
	for _, tok := range JODAllow {
		r := JODAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestJODEmpty(t *testing.T) {
	if r := JODAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestJODSplit(t *testing.T) {
	toks := JODSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

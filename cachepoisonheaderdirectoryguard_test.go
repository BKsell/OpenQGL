package main

import "testing"

func TestCPHBlockFlagged(t *testing.T) {
	for _, tok := range CPHBlock {
		in := tok
		r := CPHAudit(in)
		if !CPHHas(r, CPHReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestCPHWarnFlagged(t *testing.T) {
	for _, tok := range CPHWarn {
		r := CPHAudit(tok)
		if !CPHHas(r, CPHReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestCPHAllowSafe(t *testing.T) {
	for _, tok := range CPHAllow {
		r := CPHAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestCPHEmpty(t *testing.T) {
	if r := CPHAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestCPHSplit(t *testing.T) {
	toks := CPHSplit("a,b,c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

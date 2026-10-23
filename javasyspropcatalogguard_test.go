package main

import "testing"

func TestJSPBlockFlagged(t *testing.T) {
	for _, tok := range JSPBlock {
		in := "-D" + tok + "=x"
		r := JSPAudit(in)
		if !JSPHas(r, JSPReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestJSPWarnFlagged(t *testing.T) {
	for _, tok := range JSPWarn {
		r := JSPAudit(tok)
		if !JSPHas(r, JSPReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestJSPAllowSafe(t *testing.T) {
	for _, tok := range JSPAllow {
		r := JSPAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestJSPPrefixFlagged(t *testing.T) {
	lit := JSPPrefixLit[0]
	r := JSPAudit(lit + "something")
	if !JSPHas(r, JSPPrefixReason[0]) { t.Fatalf("prefix must flag: %s", lit) }
}

func TestJSPEmpty(t *testing.T) {
	if r := JSPAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestJSPSplit(t *testing.T) {
	toks := JSPSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

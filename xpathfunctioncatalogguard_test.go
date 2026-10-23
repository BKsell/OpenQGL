package main

import "testing"

func TestXPFBlockFlagged(t *testing.T) {
	for _, tok := range XPFBlock {
		in := tok
		r := XPFAudit(in)
		if !XPFHas(r, XPFReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestXPFWarnFlagged(t *testing.T) {
	for _, tok := range XPFWarn {
		r := XPFAudit(tok)
		if !XPFHas(r, XPFReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestXPFAllowSafe(t *testing.T) {
	for _, tok := range XPFAllow {
		r := XPFAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestXPFEmpty(t *testing.T) {
	if r := XPFAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestXPFSplit(t *testing.T) {
	toks := XPFSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

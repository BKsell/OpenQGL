package main

import "testing"

func TestLFCBlockFlagged(t *testing.T) {
	for _, tok := range LFCBlock {
		in := tok
		r := LFCAudit(in)
		if !LFCHas(r, LFCReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestLFCWarnFlagged(t *testing.T) {
	for _, tok := range LFCWarn {
		r := LFCAudit(tok)
		if !LFCHas(r, LFCReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestLFCAllowSafe(t *testing.T) {
	for _, tok := range LFCAllow {
		r := LFCAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestLFCEmpty(t *testing.T) {
	if r := LFCAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestLFCSplit(t *testing.T) {
	toks := LFCSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

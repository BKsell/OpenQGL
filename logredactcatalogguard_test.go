package main

import "testing"

func TestLRCBlockFlagged(t *testing.T) {
	for _, tok := range LRCBlock {
		in := tok
		r := LRCAudit(in)
		if !LRCHas(r, LRCReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestLRCWarnFlagged(t *testing.T) {
	for _, tok := range LRCWarn {
		r := LRCAudit(tok)
		if !LRCHas(r, LRCReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestLRCAllowSafe(t *testing.T) {
	for _, tok := range LRCAllow {
		r := LRCAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestLRCPrefixFlagged(t *testing.T) {
	lit := LRCPrefixLit[0]
	r := LRCAudit(lit + "something")
	if !LRCHas(r, LRCPrefixReason[0]) { t.Fatalf("prefix must flag: %s", lit) }
}

func TestLRCEmpty(t *testing.T) {
	if r := LRCAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestLRCSplit(t *testing.T) {
	toks := LRCSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

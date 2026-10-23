package main

import "testing"

func TestEVCBlockFlagged(t *testing.T) {
	for _, tok := range EVCBlock {
		in := tok
		r := EVCAudit(in)
		if !EVCHas(r, EVCReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestEVCWarnFlagged(t *testing.T) {
	for _, tok := range EVCWarn {
		r := EVCAudit(tok)
		if !EVCHas(r, EVCReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestEVCAllowSafe(t *testing.T) {
	for _, tok := range EVCAllow {
		r := EVCAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestEVCPrefixFlagged(t *testing.T) {
	lit := EVCPrefixLit[0]
	r := EVCAudit(lit + "something")
	if !EVCHas(r, EVCPrefixReason[0]) { t.Fatalf("prefix must flag: %s", lit) }
}

func TestEVCEmpty(t *testing.T) {
	if r := EVCAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestEVCSplit(t *testing.T) {
	toks := EVCSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

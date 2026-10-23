package main

import "testing"

func TestSTCBlockFlagged(t *testing.T) {
	for _, tok := range STCBlock {
		in := tok
		r := STCAudit(in)
		if !STCHas(r, STCReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestSTCWarnFlagged(t *testing.T) {
	for _, tok := range STCWarn {
		r := STCAudit(tok)
		if !STCHas(r, STCReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestSTCAllowSafe(t *testing.T) {
	for _, tok := range STCAllow {
		r := STCAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestSTCPrefixFlagged(t *testing.T) {
	lit := STCPrefixLit[0]
	r := STCAudit(lit + "something")
	if !STCHas(r, STCPrefixReason[0]) { t.Fatalf("prefix must flag: %s", lit) }
}

func TestSTCEmpty(t *testing.T) {
	if r := STCAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestSTCSplit(t *testing.T) {
	toks := STCSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

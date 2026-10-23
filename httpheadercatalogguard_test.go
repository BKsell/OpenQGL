package main

import "testing"

func TestHHCBlockFlagged(t *testing.T) {
	for _, tok := range HHCBlock {
		in := tok
		r := HHCAudit(in)
		if !HHCHas(r, HHCReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestHHCWarnFlagged(t *testing.T) {
	for _, tok := range HHCWarn {
		r := HHCAudit(tok)
		if !HHCHas(r, HHCReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestHHCAllowSafe(t *testing.T) {
	for _, tok := range HHCAllow {
		r := HHCAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestHHCPrefixFlagged(t *testing.T) {
	lit := HHCPrefixLit[0]
	r := HHCAudit(lit + "something")
	if !HHCHas(r, HHCPrefixReason[0]) { t.Fatalf("prefix must flag: %s", lit) }
}

func TestHHCEmpty(t *testing.T) {
	if r := HHCAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestHHCSplit(t *testing.T) {
	toks := HHCSplit("a,b,c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

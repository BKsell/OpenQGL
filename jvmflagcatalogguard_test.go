package main

import "testing"

func TestJVFBlockFlagged(t *testing.T) {
	for _, tok := range JVFBlock {
		in := tok
		r := JVFAudit(in)
		if !JVFHas(r, JVFReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestJVFWarnFlagged(t *testing.T) {
	for _, tok := range JVFWarn {
		r := JVFAudit(tok)
		if !JVFHas(r, JVFReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestJVFAllowSafe(t *testing.T) {
	for _, tok := range JVFAllow {
		r := JVFAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestJVFPrefixFlagged(t *testing.T) {
	lit := JVFPrefixLit[0]
	r := JVFAudit(lit + "something")
	if !JVFHas(r, JVFPrefixReason[0]) { t.Fatalf("prefix must flag: %s", lit) }
}

func TestJVFEmpty(t *testing.T) {
	if r := JVFAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestJVFSplit(t *testing.T) {
	toks := JVFSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

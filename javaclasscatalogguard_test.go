package main

import "testing"

func TestJCCBlockFlagged(t *testing.T) {
	for _, tok := range JCCBlock {
		in := tok
		r := JCCAudit(in)
		if !JCCHas(r, JCCReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestJCCWarnFlagged(t *testing.T) {
	for _, tok := range JCCWarn {
		r := JCCAudit(tok)
		if !JCCHas(r, JCCReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestJCCAllowSafe(t *testing.T) {
	for _, tok := range JCCAllow {
		r := JCCAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestJCCPrefixFlagged(t *testing.T) {
	lit := JCCPrefixLit[0]
	r := JCCAudit(lit + "something")
	if !JCCHas(r, JCCPrefixReason[0]) { t.Fatalf("prefix must flag: %s", lit) }
}

func TestJCCEmpty(t *testing.T) {
	if r := JCCAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestJCCSplit(t *testing.T) {
	toks := JCCSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

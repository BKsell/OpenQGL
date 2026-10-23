package main

import "testing"

func TestJPCBlockFlagged(t *testing.T) {
	for _, tok := range JPCBlock {
		in := tok
		r := JPCAudit(in)
		if !JPCHas(r, JPCReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestJPCWarnFlagged(t *testing.T) {
	for _, tok := range JPCWarn {
		r := JPCAudit(tok)
		if !JPCHas(r, JPCReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestJPCAllowSafe(t *testing.T) {
	for _, tok := range JPCAllow {
		r := JPCAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestJPCPrefixFlagged(t *testing.T) {
	lit := JPCPrefixLit[0]
	r := JPCAudit(lit + "something")
	if !JPCHas(r, JPCPrefixReason[0]) { t.Fatalf("prefix must flag: %s", lit) }
}

func TestJPCEmpty(t *testing.T) {
	if r := JPCAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestJPCSplit(t *testing.T) {
	toks := JPCSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

package main

import "testing"

func TestXKWBlockFlagged(t *testing.T) {
	for _, tok := range XKWBlock {
		in := tok
		r := XKWAudit(in)
		if !XKWHas(r, XKWReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestXKWWarnFlagged(t *testing.T) {
	for _, tok := range XKWWarn {
		r := XKWAudit(tok)
		if !XKWHas(r, XKWReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestXKWAllowSafe(t *testing.T) {
	for _, tok := range XKWAllow {
		r := XKWAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestXKWEmpty(t *testing.T) {
	if r := XKWAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestXKWSplit(t *testing.T) {
	toks := XKWSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

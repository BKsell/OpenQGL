package main

import "testing"

func TestSQLBlockFlagged(t *testing.T) {
	for _, tok := range SQLBlock {
		in := tok
		r := SQLAudit(in)
		if !SQLHas(r, SQLReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestSQLWarnFlagged(t *testing.T) {
	for _, tok := range SQLWarn {
		r := SQLAudit(tok)
		if !SQLHas(r, SQLReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestSQLAllowSafe(t *testing.T) {
	for _, tok := range SQLAllow {
		r := SQLAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestSQLEmpty(t *testing.T) {
	if r := SQLAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestSQLSplit(t *testing.T) {
	toks := SQLSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

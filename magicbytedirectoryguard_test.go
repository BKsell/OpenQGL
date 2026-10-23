package main

import "testing"

func TestMBDBlockFlagged(t *testing.T) {
	for _, tok := range MBDBlock {
		in := tok
		r := MBDAudit(in)
		if !MBDHas(r, MBDReasonBlock) { t.Fatalf("blocked token must flag: %s", tok) }
	}
}

func TestMBDWarnFlagged(t *testing.T) {
	for _, tok := range MBDWarn {
		r := MBDAudit(tok)
		if !MBDHas(r, MBDReasonWarn) { t.Fatalf("review token must warn: %s", tok) }
	}
}

func TestMBDAllowSafe(t *testing.T) {
	for _, tok := range MBDAllow {
		r := MBDAudit(tok)
		if !r.Safe { t.Fatalf("allowed token must be safe: %s (%v)", tok, r.Findings) }
	}
}

func TestMBDEmpty(t *testing.T) {
	if r := MBDAudit(""); r.Safe { t.Fatal("empty input unsafe") }
}

func TestMBDSplit(t *testing.T) {
	toks := MBDSplit("a b c")
	if len(toks) != 3 { t.Fatalf("split count %d", len(toks)) }
}

package main

import "testing"

func TestCSVBenign(t *testing.T) {
	if safe, _ := CSVAuditCell("Survival Server", 0); !safe {
		t.Fatal("ordinary text cell should pass")
	}
}

func TestCSVEquals(t *testing.T) {
	_, fs := CSVAuditCell("=1+1", 1)
	if !CSVHasReason(fs, CSVReasonFormulaEquals) {
		t.Fatalf("leading = must flag: %v", fs)
	}
}

func TestCSVPlus(t *testing.T) {
	_, fs := CSVAuditCell("+1+cmd|", 0)
	if !CSVHasReason(fs, CSVReasonFormulaPlus) {
		t.Fatalf("leading + must flag: %v", fs)
	}
}

func TestCSVMinus(t *testing.T) {
	_, fs := CSVAuditCell("-2+3", 0)
	if !CSVHasReason(fs, CSVReasonFormulaMinus) {
		t.Fatalf("leading - must flag: %v", fs)
	}
}

func TestCSVAt(t *testing.T) {
	_, fs := CSVAuditCell("@SUM(1)", 0)
	if !CSVHasReason(fs, CSVReasonFormulaAt) {
		t.Fatalf("leading @ must flag: %v", fs)
	}
}

func TestCSVDDECmd(t *testing.T) {
	_, fs := CSVAuditCell("=cmd|' /C calc'!A0", 0)
	if !CSVHasReason(fs, CSVReasonDDECmd) {
		t.Fatalf("DDE command execution must flag: %v", fs)
	}
}

func TestCSVHyperlink(t *testing.T) {
	_, fs := CSVAuditCell("=HYPERLINK(\"http://evil\")", 0)
	if !CSVHasReason(fs, CSVReasonDDECmd) {
		t.Fatalf("HYPERLINK formula must flag: %v", fs)
	}
}

func TestCSVNeutralize(t *testing.T) {
	if got := CSVNeutralize("=1+1"); got != "'=1+1" {
		t.Fatalf("formula must be prefixed with quote: %q", got)
	}
	if got := CSVNeutralize("normal"); got != "normal" {
		t.Fatalf("benign cell must not be altered: %q", got)
	}
}

func TestCSVQuoteComma(t *testing.T) {
	if got := CSVQuoteField("a,b"); got != `"a,b"` {
		t.Fatalf("comma field must be quoted: %q", got)
	}
}

func TestCSVQuoteInnerQuote(t *testing.T) {
	if got := CSVQuoteField(`a"b`); got != `"a""b"` {
		t.Fatalf("inner quote must be doubled: %q", got)
	}
}

func TestCSVQuoteNewline(t *testing.T) {
	if got := CSVQuoteField("a\nb"); got != "\"a\nb\"" {
		t.Fatalf("newline field must be quoted: %q", got)
	}
}

func TestCSVQuotePlain(t *testing.T) {
	if got := CSVQuoteField("plain"); got != "plain" {
		t.Fatalf("plain field should not be quoted: %q", got)
	}
}

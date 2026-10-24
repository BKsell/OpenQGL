package main

import "testing"

func TestE70T20ClassifyBlock(t *testing.T) {
	for _, v := range E70T20Block { if E70T20Classify(v) != E70T20ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T20ClassifyWarn(t *testing.T) {
	for _, v := range E70T20Warn { if E70T20Classify(v) != E70T20ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T20ClassifyAllow(t *testing.T) {
	for _, v := range E70T20Allow { if E70T20Classify(v) != E70T20ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T20ClassifyUnknown(t *testing.T) {
	if E70T20Classify("zzz-not-in-any-e70-catalog-99") != E70T20ClassUnknown { t.Fatal("unknown") }
}

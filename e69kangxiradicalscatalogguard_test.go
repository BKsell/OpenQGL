package main

import "testing"

func TestE69T20ClassifyBlock(t *testing.T) {
	for _, v := range E69T20Block { if E69T20Classify(v) != E69T20ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T20ClassifyWarn(t *testing.T) {
	for _, v := range E69T20Warn { if E69T20Classify(v) != E69T20ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T20ClassifyAllow(t *testing.T) {
	for _, v := range E69T20Allow { if E69T20Classify(v) != E69T20ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T20ClassifyUnknown(t *testing.T) {
	if E69T20Classify("zzz-not-in-any-e69-catalog-88") != E69T20ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE69T14ClassifyBlock(t *testing.T) {
	for _, v := range E69T14Block { if E69T14Classify(v) != E69T14ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T14ClassifyWarn(t *testing.T) {
	for _, v := range E69T14Warn { if E69T14Classify(v) != E69T14ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T14ClassifyAllow(t *testing.T) {
	for _, v := range E69T14Allow { if E69T14Classify(v) != E69T14ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T14ClassifyUnknown(t *testing.T) {
	if E69T14Classify("zzz-not-in-any-e69-catalog-88") != E69T14ClassUnknown { t.Fatal("unknown") }
}

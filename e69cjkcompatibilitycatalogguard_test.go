package main

import "testing"

func TestE69T30ClassifyBlock(t *testing.T) {
	for _, v := range E69T30Block { if E69T30Classify(v) != E69T30ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T30ClassifyWarn(t *testing.T) {
	for _, v := range E69T30Warn { if E69T30Classify(v) != E69T30ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T30ClassifyAllow(t *testing.T) {
	for _, v := range E69T30Allow { if E69T30Classify(v) != E69T30ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T30ClassifyUnknown(t *testing.T) {
	if E69T30Classify("zzz-not-in-any-e69-catalog-88") != E69T30ClassUnknown { t.Fatal("unknown") }
}

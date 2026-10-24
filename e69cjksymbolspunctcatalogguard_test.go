package main

import "testing"

func TestE69T24ClassifyBlock(t *testing.T) {
	for _, v := range E69T24Block { if E69T24Classify(v) != E69T24ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T24ClassifyWarn(t *testing.T) {
	for _, v := range E69T24Warn { if E69T24Classify(v) != E69T24ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T24ClassifyAllow(t *testing.T) {
	for _, v := range E69T24Allow { if E69T24Classify(v) != E69T24ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T24ClassifyUnknown(t *testing.T) {
	if E69T24Classify("zzz-not-in-any-e69-catalog-88") != E69T24ClassUnknown { t.Fatal("unknown") }
}

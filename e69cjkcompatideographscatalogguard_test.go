package main

import "testing"

func TestE69T41ClassifyBlock(t *testing.T) {
	for _, v := range E69T41Block { if E69T41Classify(v) != E69T41ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T41ClassifyWarn(t *testing.T) {
	for _, v := range E69T41Warn { if E69T41Classify(v) != E69T41ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T41ClassifyAllow(t *testing.T) {
	for _, v := range E69T41Allow { if E69T41Classify(v) != E69T41ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T41ClassifyUnknown(t *testing.T) {
	if E69T41Classify("zzz-not-in-any-e69-catalog-88") != E69T41ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE69T21ClassifyBlock(t *testing.T) {
	for _, v := range E69T21Block { if E69T21Classify(v) != E69T21ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T21ClassifyWarn(t *testing.T) {
	for _, v := range E69T21Warn { if E69T21Classify(v) != E69T21ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T21ClassifyAllow(t *testing.T) {
	for _, v := range E69T21Allow { if E69T21Classify(v) != E69T21ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T21ClassifyUnknown(t *testing.T) {
	if E69T21Classify("zzz-not-in-any-e69-catalog-88") != E69T21ClassUnknown { t.Fatal("unknown") }
}

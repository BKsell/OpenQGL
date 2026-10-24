package main

import "testing"

func TestE69T34ClassifyBlock(t *testing.T) {
	for _, v := range E69T34Block { if E69T34Classify(v) != E69T34ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T34ClassifyWarn(t *testing.T) {
	for _, v := range E69T34Warn { if E69T34Classify(v) != E69T34ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T34ClassifyAllow(t *testing.T) {
	for _, v := range E69T34Allow { if E69T34Classify(v) != E69T34ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T34ClassifyUnknown(t *testing.T) {
	if E69T34Classify("zzz-not-in-any-e69-catalog-88") != E69T34ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE69T39ClassifyBlock(t *testing.T) {
	for _, v := range E69T39Block { if E69T39Classify(v) != E69T39ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T39ClassifyWarn(t *testing.T) {
	for _, v := range E69T39Warn { if E69T39Classify(v) != E69T39ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T39ClassifyAllow(t *testing.T) {
	for _, v := range E69T39Allow { if E69T39Classify(v) != E69T39ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T39ClassifyUnknown(t *testing.T) {
	if E69T39Classify("zzz-not-in-any-e69-catalog-88") != E69T39ClassUnknown { t.Fatal("unknown") }
}

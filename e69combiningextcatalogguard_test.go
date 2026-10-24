package main

import "testing"

func TestE69T37ClassifyBlock(t *testing.T) {
	for _, v := range E69T37Block { if E69T37Classify(v) != E69T37ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T37ClassifyWarn(t *testing.T) {
	for _, v := range E69T37Warn { if E69T37Classify(v) != E69T37ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T37ClassifyAllow(t *testing.T) {
	for _, v := range E69T37Allow { if E69T37Classify(v) != E69T37ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T37ClassifyUnknown(t *testing.T) {
	if E69T37Classify("zzz-not-in-any-e69-catalog-88") != E69T37ClassUnknown { t.Fatal("unknown") }
}

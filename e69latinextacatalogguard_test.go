package main

import "testing"

func TestE69T01ClassifyBlock(t *testing.T) {
	for _, v := range E69T01Block { if E69T01Classify(v) != E69T01ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T01ClassifyWarn(t *testing.T) {
	for _, v := range E69T01Warn { if E69T01Classify(v) != E69T01ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T01ClassifyAllow(t *testing.T) {
	for _, v := range E69T01Allow { if E69T01Classify(v) != E69T01ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T01ClassifyUnknown(t *testing.T) {
	if E69T01Classify("zzz-not-in-any-e69-catalog-88") != E69T01ClassUnknown { t.Fatal("unknown") }
}

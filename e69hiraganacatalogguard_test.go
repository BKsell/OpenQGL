package main

import "testing"

func TestE69T25ClassifyBlock(t *testing.T) {
	for _, v := range E69T25Block { if E69T25Classify(v) != E69T25ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T25ClassifyWarn(t *testing.T) {
	for _, v := range E69T25Warn { if E69T25Classify(v) != E69T25ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T25ClassifyAllow(t *testing.T) {
	for _, v := range E69T25Allow { if E69T25Classify(v) != E69T25ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T25ClassifyUnknown(t *testing.T) {
	if E69T25Classify("zzz-not-in-any-e69-catalog-88") != E69T25ClassUnknown { t.Fatal("unknown") }
}

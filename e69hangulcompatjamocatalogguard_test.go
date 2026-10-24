package main

import "testing"

func TestE69T28ClassifyBlock(t *testing.T) {
	for _, v := range E69T28Block { if E69T28Classify(v) != E69T28ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T28ClassifyWarn(t *testing.T) {
	for _, v := range E69T28Warn { if E69T28Classify(v) != E69T28ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T28ClassifyAllow(t *testing.T) {
	for _, v := range E69T28Allow { if E69T28Classify(v) != E69T28ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T28ClassifyUnknown(t *testing.T) {
	if E69T28Classify("zzz-not-in-any-e69-catalog-88") != E69T28ClassUnknown { t.Fatal("unknown") }
}

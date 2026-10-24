package main

import "testing"

func TestE69T00ClassifyBlock(t *testing.T) {
	for _, v := range E69T00Block { if E69T00Classify(v) != E69T00ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T00ClassifyWarn(t *testing.T) {
	for _, v := range E69T00Warn { if E69T00Classify(v) != E69T00ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T00ClassifyAllow(t *testing.T) {
	for _, v := range E69T00Allow { if E69T00Classify(v) != E69T00ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T00ClassifyUnknown(t *testing.T) {
	if E69T00Classify("zzz-not-in-any-e69-catalog-88") != E69T00ClassUnknown { t.Fatal("unknown") }
}

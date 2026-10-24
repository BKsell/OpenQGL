package main

import "testing"

func TestE69T17ClassifyBlock(t *testing.T) {
	for _, v := range E69T17Block { if E69T17Classify(v) != E69T17ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T17ClassifyWarn(t *testing.T) {
	for _, v := range E69T17Warn { if E69T17Classify(v) != E69T17ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T17ClassifyAllow(t *testing.T) {
	for _, v := range E69T17Allow { if E69T17Classify(v) != E69T17ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T17ClassifyUnknown(t *testing.T) {
	if E69T17Classify("zzz-not-in-any-e69-catalog-88") != E69T17ClassUnknown { t.Fatal("unknown") }
}

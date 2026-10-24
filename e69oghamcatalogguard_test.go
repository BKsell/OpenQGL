package main

import "testing"

func TestE69T11ClassifyBlock(t *testing.T) {
	for _, v := range E69T11Block { if E69T11Classify(v) != E69T11ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T11ClassifyWarn(t *testing.T) {
	for _, v := range E69T11Warn { if E69T11Classify(v) != E69T11ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T11ClassifyAllow(t *testing.T) {
	for _, v := range E69T11Allow { if E69T11Classify(v) != E69T11ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T11ClassifyUnknown(t *testing.T) {
	if E69T11Classify("zzz-not-in-any-e69-catalog-88") != E69T11ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE69T10ClassifyBlock(t *testing.T) {
	for _, v := range E69T10Block { if E69T10Classify(v) != E69T10ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T10ClassifyWarn(t *testing.T) {
	for _, v := range E69T10Warn { if E69T10Classify(v) != E69T10ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T10ClassifyAllow(t *testing.T) {
	for _, v := range E69T10Allow { if E69T10Classify(v) != E69T10ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T10ClassifyUnknown(t *testing.T) {
	if E69T10Classify("zzz-not-in-any-e69-catalog-88") != E69T10ClassUnknown { t.Fatal("unknown") }
}

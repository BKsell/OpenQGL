package main

import "testing"

func TestE69T32ClassifyBlock(t *testing.T) {
	for _, v := range E69T32Block { if E69T32Classify(v) != E69T32ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T32ClassifyWarn(t *testing.T) {
	for _, v := range E69T32Warn { if E69T32Classify(v) != E69T32ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T32ClassifyAllow(t *testing.T) {
	for _, v := range E69T32Allow { if E69T32Classify(v) != E69T32ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T32ClassifyUnknown(t *testing.T) {
	if E69T32Classify("zzz-not-in-any-e69-catalog-88") != E69T32ClassUnknown { t.Fatal("unknown") }
}

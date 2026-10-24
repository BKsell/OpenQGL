package main

import "testing"

func TestE69T03ClassifyBlock(t *testing.T) {
	for _, v := range E69T03Block { if E69T03Classify(v) != E69T03ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T03ClassifyWarn(t *testing.T) {
	for _, v := range E69T03Warn { if E69T03Classify(v) != E69T03ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T03ClassifyAllow(t *testing.T) {
	for _, v := range E69T03Allow { if E69T03Classify(v) != E69T03ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T03ClassifyUnknown(t *testing.T) {
	if E69T03Classify("zzz-not-in-any-e69-catalog-88") != E69T03ClassUnknown { t.Fatal("unknown") }
}

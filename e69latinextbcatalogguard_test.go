package main

import "testing"

func TestE69T02ClassifyBlock(t *testing.T) {
	for _, v := range E69T02Block { if E69T02Classify(v) != E69T02ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T02ClassifyWarn(t *testing.T) {
	for _, v := range E69T02Warn { if E69T02Classify(v) != E69T02ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T02ClassifyAllow(t *testing.T) {
	for _, v := range E69T02Allow { if E69T02Classify(v) != E69T02ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T02ClassifyUnknown(t *testing.T) {
	if E69T02Classify("zzz-not-in-any-e69-catalog-88") != E69T02ClassUnknown { t.Fatal("unknown") }
}

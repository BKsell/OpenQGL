package main

import "testing"

func TestE69T31ClassifyBlock(t *testing.T) {
	for _, v := range E69T31Block { if E69T31Classify(v) != E69T31ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T31ClassifyWarn(t *testing.T) {
	for _, v := range E69T31Warn { if E69T31Classify(v) != E69T31ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T31ClassifyAllow(t *testing.T) {
	for _, v := range E69T31Allow { if E69T31Classify(v) != E69T31ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T31ClassifyUnknown(t *testing.T) {
	if E69T31Classify("zzz-not-in-any-e69-catalog-88") != E69T31ClassUnknown { t.Fatal("unknown") }
}

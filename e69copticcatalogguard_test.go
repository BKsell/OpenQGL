package main

import "testing"

func TestE69T16ClassifyBlock(t *testing.T) {
	for _, v := range E69T16Block { if E69T16Classify(v) != E69T16ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T16ClassifyWarn(t *testing.T) {
	for _, v := range E69T16Warn { if E69T16Classify(v) != E69T16ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T16ClassifyAllow(t *testing.T) {
	for _, v := range E69T16Allow { if E69T16Classify(v) != E69T16ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T16ClassifyUnknown(t *testing.T) {
	if E69T16Classify("zzz-not-in-any-e69-catalog-88") != E69T16ClassUnknown { t.Fatal("unknown") }
}

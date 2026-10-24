package main

import "testing"

func TestE69T13ClassifyBlock(t *testing.T) {
	for _, v := range E69T13Block { if E69T13Classify(v) != E69T13ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T13ClassifyWarn(t *testing.T) {
	for _, v := range E69T13Warn { if E69T13Classify(v) != E69T13ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T13ClassifyAllow(t *testing.T) {
	for _, v := range E69T13Allow { if E69T13Classify(v) != E69T13ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T13ClassifyUnknown(t *testing.T) {
	if E69T13Classify("zzz-not-in-any-e69-catalog-88") != E69T13ClassUnknown { t.Fatal("unknown") }
}

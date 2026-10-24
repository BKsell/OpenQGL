package main

import "testing"

func TestE69T29ClassifyBlock(t *testing.T) {
	for _, v := range E69T29Block { if E69T29Classify(v) != E69T29ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T29ClassifyWarn(t *testing.T) {
	for _, v := range E69T29Warn { if E69T29Classify(v) != E69T29ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T29ClassifyAllow(t *testing.T) {
	for _, v := range E69T29Allow { if E69T29Classify(v) != E69T29ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T29ClassifyUnknown(t *testing.T) {
	if E69T29Classify("zzz-not-in-any-e69-catalog-88") != E69T29ClassUnknown { t.Fatal("unknown") }
}

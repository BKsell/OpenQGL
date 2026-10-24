package main

import "testing"

func TestE69T22ClassifyBlock(t *testing.T) {
	for _, v := range E69T22Block { if E69T22Classify(v) != E69T22ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T22ClassifyWarn(t *testing.T) {
	for _, v := range E69T22Warn { if E69T22Classify(v) != E69T22ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T22ClassifyAllow(t *testing.T) {
	for _, v := range E69T22Allow { if E69T22Classify(v) != E69T22ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T22ClassifyUnknown(t *testing.T) {
	if E69T22Classify("zzz-not-in-any-e69-catalog-88") != E69T22ClassUnknown { t.Fatal("unknown") }
}

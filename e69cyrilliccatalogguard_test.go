package main

import "testing"

func TestE69T07ClassifyBlock(t *testing.T) {
	for _, v := range E69T07Block { if E69T07Classify(v) != E69T07ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T07ClassifyWarn(t *testing.T) {
	for _, v := range E69T07Warn { if E69T07Classify(v) != E69T07ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T07ClassifyAllow(t *testing.T) {
	for _, v := range E69T07Allow { if E69T07Classify(v) != E69T07ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T07ClassifyUnknown(t *testing.T) {
	if E69T07Classify("zzz-not-in-any-e69-catalog-88") != E69T07ClassUnknown { t.Fatal("unknown") }
}

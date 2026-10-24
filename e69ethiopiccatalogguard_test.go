package main

import "testing"

func TestE69T09ClassifyBlock(t *testing.T) {
	for _, v := range E69T09Block { if E69T09Classify(v) != E69T09ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T09ClassifyWarn(t *testing.T) {
	for _, v := range E69T09Warn { if E69T09Classify(v) != E69T09ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T09ClassifyAllow(t *testing.T) {
	for _, v := range E69T09Allow { if E69T09Classify(v) != E69T09ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T09ClassifyUnknown(t *testing.T) {
	if E69T09Classify("zzz-not-in-any-e69-catalog-88") != E69T09ClassUnknown { t.Fatal("unknown") }
}

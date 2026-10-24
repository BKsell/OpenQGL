package main

import "testing"

func TestE69T35ClassifyBlock(t *testing.T) {
	for _, v := range E69T35Block { if E69T35Classify(v) != E69T35ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T35ClassifyWarn(t *testing.T) {
	for _, v := range E69T35Warn { if E69T35Classify(v) != E69T35ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T35ClassifyAllow(t *testing.T) {
	for _, v := range E69T35Allow { if E69T35Classify(v) != E69T35ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T35ClassifyUnknown(t *testing.T) {
	if E69T35Classify("zzz-not-in-any-e69-catalog-88") != E69T35ClassUnknown { t.Fatal("unknown") }
}

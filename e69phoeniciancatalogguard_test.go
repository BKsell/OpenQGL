package main

import "testing"

func TestE69T42ClassifyBlock(t *testing.T) {
	for _, v := range E69T42Block { if E69T42Classify(v) != E69T42ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T42ClassifyWarn(t *testing.T) {
	for _, v := range E69T42Warn { if E69T42Classify(v) != E69T42ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T42ClassifyAllow(t *testing.T) {
	for _, v := range E69T42Allow { if E69T42Classify(v) != E69T42ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T42ClassifyUnknown(t *testing.T) {
	if E69T42Classify("zzz-not-in-any-e69-catalog-88") != E69T42ClassUnknown { t.Fatal("unknown") }
}

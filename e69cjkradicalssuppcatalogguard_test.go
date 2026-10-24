package main

import "testing"

func TestE69T19ClassifyBlock(t *testing.T) {
	for _, v := range E69T19Block { if E69T19Classify(v) != E69T19ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T19ClassifyWarn(t *testing.T) {
	for _, v := range E69T19Warn { if E69T19Classify(v) != E69T19ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T19ClassifyAllow(t *testing.T) {
	for _, v := range E69T19Allow { if E69T19Classify(v) != E69T19ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T19ClassifyUnknown(t *testing.T) {
	if E69T19Classify("zzz-not-in-any-e69-catalog-88") != E69T19ClassUnknown { t.Fatal("unknown") }
}

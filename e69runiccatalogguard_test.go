package main

import "testing"

func TestE69T12ClassifyBlock(t *testing.T) {
	for _, v := range E69T12Block { if E69T12Classify(v) != E69T12ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T12ClassifyWarn(t *testing.T) {
	for _, v := range E69T12Warn { if E69T12Classify(v) != E69T12ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T12ClassifyAllow(t *testing.T) {
	for _, v := range E69T12Allow { if E69T12Classify(v) != E69T12ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T12ClassifyUnknown(t *testing.T) {
	if E69T12Classify("zzz-not-in-any-e69-catalog-88") != E69T12ClassUnknown { t.Fatal("unknown") }
}

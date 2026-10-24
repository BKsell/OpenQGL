package main

import "testing"

func TestE69T04ClassifyBlock(t *testing.T) {
	for _, v := range E69T04Block { if E69T04Classify(v) != E69T04ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T04ClassifyWarn(t *testing.T) {
	for _, v := range E69T04Warn { if E69T04Classify(v) != E69T04ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T04ClassifyAllow(t *testing.T) {
	for _, v := range E69T04Allow { if E69T04Classify(v) != E69T04ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T04ClassifyUnknown(t *testing.T) {
	if E69T04Classify("zzz-not-in-any-e69-catalog-88") != E69T04ClassUnknown { t.Fatal("unknown") }
}

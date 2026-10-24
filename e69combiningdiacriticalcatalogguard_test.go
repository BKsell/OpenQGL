package main

import "testing"

func TestE69T05ClassifyBlock(t *testing.T) {
	for _, v := range E69T05Block { if E69T05Classify(v) != E69T05ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T05ClassifyWarn(t *testing.T) {
	for _, v := range E69T05Warn { if E69T05Classify(v) != E69T05ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T05ClassifyAllow(t *testing.T) {
	for _, v := range E69T05Allow { if E69T05Classify(v) != E69T05ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T05ClassifyUnknown(t *testing.T) {
	if E69T05Classify("zzz-not-in-any-e69-catalog-88") != E69T05ClassUnknown { t.Fatal("unknown") }
}

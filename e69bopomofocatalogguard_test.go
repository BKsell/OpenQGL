package main

import "testing"

func TestE69T27ClassifyBlock(t *testing.T) {
	for _, v := range E69T27Block { if E69T27Classify(v) != E69T27ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T27ClassifyWarn(t *testing.T) {
	for _, v := range E69T27Warn { if E69T27Classify(v) != E69T27ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T27ClassifyAllow(t *testing.T) {
	for _, v := range E69T27Allow { if E69T27Classify(v) != E69T27ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T27ClassifyUnknown(t *testing.T) {
	if E69T27Classify("zzz-not-in-any-e69-catalog-88") != E69T27ClassUnknown { t.Fatal("unknown") }
}

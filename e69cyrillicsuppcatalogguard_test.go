package main

import "testing"

func TestE69T08ClassifyBlock(t *testing.T) {
	for _, v := range E69T08Block { if E69T08Classify(v) != E69T08ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T08ClassifyWarn(t *testing.T) {
	for _, v := range E69T08Warn { if E69T08Classify(v) != E69T08ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T08ClassifyAllow(t *testing.T) {
	for _, v := range E69T08Allow { if E69T08Classify(v) != E69T08ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T08ClassifyUnknown(t *testing.T) {
	if E69T08Classify("zzz-not-in-any-e69-catalog-88") != E69T08ClassUnknown { t.Fatal("unknown") }
}

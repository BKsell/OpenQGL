package main

import "testing"

func TestE69T15ClassifyBlock(t *testing.T) {
	for _, v := range E69T15Block { if E69T15Classify(v) != E69T15ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T15ClassifyWarn(t *testing.T) {
	for _, v := range E69T15Warn { if E69T15Classify(v) != E69T15ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T15ClassifyAllow(t *testing.T) {
	for _, v := range E69T15Allow { if E69T15Classify(v) != E69T15ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T15ClassifyUnknown(t *testing.T) {
	if E69T15Classify("zzz-not-in-any-e69-catalog-88") != E69T15ClassUnknown { t.Fatal("unknown") }
}

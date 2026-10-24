package main

import "testing"

func TestE69U01ClassifyBlock(t *testing.T) {
	for _, v := range E69U01Block { if E69U01Classify(v) != E69U01ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U01ClassifyWarn(t *testing.T) {
	for _, v := range E69U01Warn { if E69U01Classify(v) != E69U01ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U01ClassifyAllow(t *testing.T) {
	for _, v := range E69U01Allow { if E69U01Classify(v) != E69U01ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U01ClassifyUnknown(t *testing.T) {
	if E69U01Classify("zzz-not-in-any-e69-catalog-88") != E69U01ClassUnknown { t.Fatal("unknown") }
}

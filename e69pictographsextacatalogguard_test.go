package main

import "testing"

func TestE69U05ClassifyBlock(t *testing.T) {
	for _, v := range E69U05Block { if E69U05Classify(v) != E69U05ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U05ClassifyWarn(t *testing.T) {
	for _, v := range E69U05Warn { if E69U05Classify(v) != E69U05ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U05ClassifyAllow(t *testing.T) {
	for _, v := range E69U05Allow { if E69U05Classify(v) != E69U05ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U05ClassifyUnknown(t *testing.T) {
	if E69U05Classify("zzz-not-in-any-e69-catalog-88") != E69U05ClassUnknown { t.Fatal("unknown") }
}

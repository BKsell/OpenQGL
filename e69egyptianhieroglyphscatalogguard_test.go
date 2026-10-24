package main

import "testing"

func TestE69U09ClassifyBlock(t *testing.T) {
	for _, v := range E69U09Block { if E69U09Classify(v) != E69U09ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U09ClassifyWarn(t *testing.T) {
	for _, v := range E69U09Warn { if E69U09Classify(v) != E69U09ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U09ClassifyAllow(t *testing.T) {
	for _, v := range E69U09Allow { if E69U09Classify(v) != E69U09ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U09ClassifyUnknown(t *testing.T) {
	if E69U09Classify("zzz-not-in-any-e69-catalog-88") != E69U09ClassUnknown { t.Fatal("unknown") }
}

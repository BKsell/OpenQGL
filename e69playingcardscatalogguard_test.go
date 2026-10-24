package main

import "testing"

func TestE69U12ClassifyBlock(t *testing.T) {
	for _, v := range E69U12Block { if E69U12Classify(v) != E69U12ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U12ClassifyWarn(t *testing.T) {
	for _, v := range E69U12Warn { if E69U12Classify(v) != E69U12ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U12ClassifyAllow(t *testing.T) {
	for _, v := range E69U12Allow { if E69U12Classify(v) != E69U12ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U12ClassifyUnknown(t *testing.T) {
	if E69U12Classify("zzz-not-in-any-e69-catalog-88") != E69U12ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE69U03ClassifyBlock(t *testing.T) {
	for _, v := range E69U03Block { if E69U03Classify(v) != E69U03ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U03ClassifyWarn(t *testing.T) {
	for _, v := range E69U03Warn { if E69U03Classify(v) != E69U03ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U03ClassifyAllow(t *testing.T) {
	for _, v := range E69U03Allow { if E69U03Classify(v) != E69U03ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U03ClassifyUnknown(t *testing.T) {
	if E69U03Classify("zzz-not-in-any-e69-catalog-88") != E69U03ClassUnknown { t.Fatal("unknown") }
}

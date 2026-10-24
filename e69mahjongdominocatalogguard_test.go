package main

import "testing"

func TestE69U11ClassifyBlock(t *testing.T) {
	for _, v := range E69U11Block { if E69U11Classify(v) != E69U11ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U11ClassifyWarn(t *testing.T) {
	for _, v := range E69U11Warn { if E69U11Classify(v) != E69U11ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U11ClassifyAllow(t *testing.T) {
	for _, v := range E69U11Allow { if E69U11Classify(v) != E69U11ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U11ClassifyUnknown(t *testing.T) {
	if E69U11Classify("zzz-not-in-any-e69-catalog-88") != E69U11ClassUnknown { t.Fatal("unknown") }
}

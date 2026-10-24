package main

import "testing"

func TestE69U07ClassifyBlock(t *testing.T) {
	for _, v := range E69U07Block { if E69U07Classify(v) != E69U07ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U07ClassifyWarn(t *testing.T) {
	for _, v := range E69U07Warn { if E69U07Classify(v) != E69U07ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U07ClassifyAllow(t *testing.T) {
	for _, v := range E69U07Allow { if E69U07Classify(v) != E69U07ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U07ClassifyUnknown(t *testing.T) {
	if E69U07Classify("zzz-not-in-any-e69-catalog-88") != E69U07ClassUnknown { t.Fatal("unknown") }
}

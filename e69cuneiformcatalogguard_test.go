package main

import "testing"

func TestE69U08ClassifyBlock(t *testing.T) {
	for _, v := range E69U08Block { if E69U08Classify(v) != E69U08ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U08ClassifyWarn(t *testing.T) {
	for _, v := range E69U08Warn { if E69U08Classify(v) != E69U08ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U08ClassifyAllow(t *testing.T) {
	for _, v := range E69U08Allow { if E69U08Classify(v) != E69U08ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U08ClassifyUnknown(t *testing.T) {
	if E69U08Classify("zzz-not-in-any-e69-catalog-88") != E69U08ClassUnknown { t.Fatal("unknown") }
}

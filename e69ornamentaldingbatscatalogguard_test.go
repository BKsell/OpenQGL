package main

import "testing"

func TestE69U00ClassifyBlock(t *testing.T) {
	for _, v := range E69U00Block { if E69U00Classify(v) != E69U00ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U00ClassifyWarn(t *testing.T) {
	for _, v := range E69U00Warn { if E69U00Classify(v) != E69U00ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U00ClassifyAllow(t *testing.T) {
	for _, v := range E69U00Allow { if E69U00Classify(v) != E69U00ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U00ClassifyUnknown(t *testing.T) {
	if E69U00Classify("zzz-not-in-any-e69-catalog-88") != E69U00ClassUnknown { t.Fatal("unknown") }
}

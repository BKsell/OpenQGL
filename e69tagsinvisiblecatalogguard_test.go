package main

import "testing"

func TestE69U06ClassifyBlock(t *testing.T) {
	for _, v := range E69U06Block { if E69U06Classify(v) != E69U06ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U06ClassifyWarn(t *testing.T) {
	for _, v := range E69U06Warn { if E69U06Classify(v) != E69U06ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U06ClassifyAllow(t *testing.T) {
	for _, v := range E69U06Allow { if E69U06Classify(v) != E69U06ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U06ClassifyUnknown(t *testing.T) {
	if E69U06Classify("zzz-not-in-any-e69-catalog-88") != E69U06ClassUnknown { t.Fatal("unknown") }
}

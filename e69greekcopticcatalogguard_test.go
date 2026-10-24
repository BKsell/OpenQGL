package main

import "testing"

func TestE69T06ClassifyBlock(t *testing.T) {
	for _, v := range E69T06Block { if E69T06Classify(v) != E69T06ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T06ClassifyWarn(t *testing.T) {
	for _, v := range E69T06Warn { if E69T06Classify(v) != E69T06ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T06ClassifyAllow(t *testing.T) {
	for _, v := range E69T06Allow { if E69T06Classify(v) != E69T06ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T06ClassifyUnknown(t *testing.T) {
	if E69T06Classify("zzz-not-in-any-e69-catalog-88") != E69T06ClassUnknown { t.Fatal("unknown") }
}

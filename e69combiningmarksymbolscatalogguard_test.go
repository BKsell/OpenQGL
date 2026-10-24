package main

import "testing"

func TestE69T23ClassifyBlock(t *testing.T) {
	for _, v := range E69T23Block { if E69T23Classify(v) != E69T23ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T23ClassifyWarn(t *testing.T) {
	for _, v := range E69T23Warn { if E69T23Classify(v) != E69T23ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T23ClassifyAllow(t *testing.T) {
	for _, v := range E69T23Allow { if E69T23Classify(v) != E69T23ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T23ClassifyUnknown(t *testing.T) {
	if E69T23Classify("zzz-not-in-any-e69-catalog-88") != E69T23ClassUnknown { t.Fatal("unknown") }
}

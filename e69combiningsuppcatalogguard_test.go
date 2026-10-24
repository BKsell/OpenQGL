package main

import "testing"

func TestE69T38ClassifyBlock(t *testing.T) {
	for _, v := range E69T38Block { if E69T38Classify(v) != E69T38ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T38ClassifyWarn(t *testing.T) {
	for _, v := range E69T38Warn { if E69T38Classify(v) != E69T38ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T38ClassifyAllow(t *testing.T) {
	for _, v := range E69T38Allow { if E69T38Classify(v) != E69T38ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T38ClassifyUnknown(t *testing.T) {
	if E69T38Classify("zzz-not-in-any-e69-catalog-88") != E69T38ClassUnknown { t.Fatal("unknown") }
}

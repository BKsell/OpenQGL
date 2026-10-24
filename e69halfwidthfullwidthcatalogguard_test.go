package main

import "testing"

func TestE69T36ClassifyBlock(t *testing.T) {
	for _, v := range E69T36Block { if E69T36Classify(v) != E69T36ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T36ClassifyWarn(t *testing.T) {
	for _, v := range E69T36Warn { if E69T36Classify(v) != E69T36ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T36ClassifyAllow(t *testing.T) {
	for _, v := range E69T36Allow { if E69T36Classify(v) != E69T36ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T36ClassifyUnknown(t *testing.T) {
	if E69T36Classify("zzz-not-in-any-e69-catalog-88") != E69T36ClassUnknown { t.Fatal("unknown") }
}

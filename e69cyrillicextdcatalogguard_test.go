package main

import "testing"

func TestE69T43ClassifyBlock(t *testing.T) {
	for _, v := range E69T43Block { if E69T43Classify(v) != E69T43ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T43ClassifyWarn(t *testing.T) {
	for _, v := range E69T43Warn { if E69T43Classify(v) != E69T43ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T43ClassifyAllow(t *testing.T) {
	for _, v := range E69T43Allow { if E69T43Classify(v) != E69T43ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T43ClassifyUnknown(t *testing.T) {
	if E69T43Classify("zzz-not-in-any-e69-catalog-88") != E69T43ClassUnknown { t.Fatal("unknown") }
}

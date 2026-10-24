package main

import "testing"

func TestE69T33ClassifyBlock(t *testing.T) {
	for _, v := range E69T33Block { if E69T33Classify(v) != E69T33ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T33ClassifyWarn(t *testing.T) {
	for _, v := range E69T33Warn { if E69T33Classify(v) != E69T33ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T33ClassifyAllow(t *testing.T) {
	for _, v := range E69T33Allow { if E69T33Classify(v) != E69T33ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T33ClassifyUnknown(t *testing.T) {
	if E69T33Classify("zzz-not-in-any-e69-catalog-88") != E69T33ClassUnknown { t.Fatal("unknown") }
}

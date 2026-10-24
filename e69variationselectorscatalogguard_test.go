package main

import "testing"

func TestE69T40ClassifyBlock(t *testing.T) {
	for _, v := range E69T40Block { if E69T40Classify(v) != E69T40ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69T40ClassifyWarn(t *testing.T) {
	for _, v := range E69T40Warn { if E69T40Classify(v) != E69T40ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69T40ClassifyAllow(t *testing.T) {
	for _, v := range E69T40Allow { if E69T40Classify(v) != E69T40ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69T40ClassifyUnknown(t *testing.T) {
	if E69T40Classify("zzz-not-in-any-e69-catalog-88") != E69T40ClassUnknown { t.Fatal("unknown") }
}

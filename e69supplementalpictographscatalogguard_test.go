package main

import "testing"

func TestE69U02ClassifyBlock(t *testing.T) {
	for _, v := range E69U02Block { if E69U02Classify(v) != E69U02ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U02ClassifyWarn(t *testing.T) {
	for _, v := range E69U02Warn { if E69U02Classify(v) != E69U02ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U02ClassifyAllow(t *testing.T) {
	for _, v := range E69U02Allow { if E69U02Classify(v) != E69U02ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U02ClassifyUnknown(t *testing.T) {
	if E69U02Classify("zzz-not-in-any-e69-catalog-88") != E69U02ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE69U10ClassifyBlock(t *testing.T) {
	for _, v := range E69U10Block { if E69U10Classify(v) != E69U10ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U10ClassifyWarn(t *testing.T) {
	for _, v := range E69U10Warn { if E69U10Classify(v) != E69U10ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U10ClassifyAllow(t *testing.T) {
	for _, v := range E69U10Allow { if E69U10Classify(v) != E69U10ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U10ClassifyUnknown(t *testing.T) {
	if E69U10Classify("zzz-not-in-any-e69-catalog-88") != E69U10ClassUnknown { t.Fatal("unknown") }
}

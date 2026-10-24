package main

import "testing"

func TestE69U04ClassifyBlock(t *testing.T) {
	for _, v := range E69U04Block { if E69U04Classify(v) != E69U04ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U04ClassifyWarn(t *testing.T) {
	for _, v := range E69U04Warn { if E69U04Classify(v) != E69U04ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U04ClassifyAllow(t *testing.T) {
	for _, v := range E69U04Allow { if E69U04Classify(v) != E69U04ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U04ClassifyUnknown(t *testing.T) {
	if E69U04Classify("zzz-not-in-any-e69-catalog-88") != E69U04ClassUnknown { t.Fatal("unknown") }
}

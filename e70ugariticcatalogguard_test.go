package main

import "testing"

func TestE70U04ClassifyBlock(t *testing.T) {
	for _, v := range E70U04Block { if E70U04Classify(v) != E70U04ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U04ClassifyWarn(t *testing.T) {
	for _, v := range E70U04Warn { if E70U04Classify(v) != E70U04ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U04ClassifyAllow(t *testing.T) {
	for _, v := range E70U04Allow { if E70U04Classify(v) != E70U04ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U04ClassifyUnknown(t *testing.T) {
	if E70U04Classify("zzz-not-in-any-e70-catalog-99") != E70U04ClassUnknown { t.Fatal("unknown") }
}

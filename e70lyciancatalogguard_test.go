package main

import "testing"

func TestE70U01ClassifyBlock(t *testing.T) {
	for _, v := range E70U01Block { if E70U01Classify(v) != E70U01ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U01ClassifyWarn(t *testing.T) {
	for _, v := range E70U01Warn { if E70U01Classify(v) != E70U01ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U01ClassifyAllow(t *testing.T) {
	for _, v := range E70U01Allow { if E70U01Classify(v) != E70U01ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U01ClassifyUnknown(t *testing.T) {
	if E70U01Classify("zzz-not-in-any-e70-catalog-99") != E70U01ClassUnknown { t.Fatal("unknown") }
}

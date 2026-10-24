package main

import "testing"

func TestE70U05ClassifyBlock(t *testing.T) {
	for _, v := range E70U05Block { if E70U05Classify(v) != E70U05ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U05ClassifyWarn(t *testing.T) {
	for _, v := range E70U05Warn { if E70U05Classify(v) != E70U05ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U05ClassifyAllow(t *testing.T) {
	for _, v := range E70U05Allow { if E70U05Classify(v) != E70U05ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U05ClassifyUnknown(t *testing.T) {
	if E70U05Classify("zzz-not-in-any-e70-catalog-99") != E70U05ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70U09ClassifyBlock(t *testing.T) {
	for _, v := range E70U09Block { if E70U09Classify(v) != E70U09ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U09ClassifyWarn(t *testing.T) {
	for _, v := range E70U09Warn { if E70U09Classify(v) != E70U09ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U09ClassifyAllow(t *testing.T) {
	for _, v := range E70U09Allow { if E70U09Classify(v) != E70U09ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U09ClassifyUnknown(t *testing.T) {
	if E70U09Classify("zzz-not-in-any-e70-catalog-99") != E70U09ClassUnknown { t.Fatal("unknown") }
}

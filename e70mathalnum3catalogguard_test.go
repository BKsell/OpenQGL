package main

import "testing"

func TestE70U12ClassifyBlock(t *testing.T) {
	for _, v := range E70U12Block { if E70U12Classify(v) != E70U12ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U12ClassifyWarn(t *testing.T) {
	for _, v := range E70U12Warn { if E70U12Classify(v) != E70U12ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U12ClassifyAllow(t *testing.T) {
	for _, v := range E70U12Allow { if E70U12Classify(v) != E70U12ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U12ClassifyUnknown(t *testing.T) {
	if E70U12Classify("zzz-not-in-any-e70-catalog-99") != E70U12ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70U03ClassifyBlock(t *testing.T) {
	for _, v := range E70U03Block { if E70U03Classify(v) != E70U03ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U03ClassifyWarn(t *testing.T) {
	for _, v := range E70U03Warn { if E70U03Classify(v) != E70U03ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U03ClassifyAllow(t *testing.T) {
	for _, v := range E70U03Allow { if E70U03Classify(v) != E70U03ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U03ClassifyUnknown(t *testing.T) {
	if E70U03Classify("zzz-not-in-any-e70-catalog-99") != E70U03ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70HD3ClassifyBlock(t *testing.T) {
	for _, v := range E70HD3Block { if E70HD3Classify(v) != E70HD3ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70HD3ClassifyWarn(t *testing.T) {
	for _, v := range E70HD3Warn { if E70HD3Classify(v) != E70HD3ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70HD3ClassifyAllow(t *testing.T) {
	for _, v := range E70HD3Allow { if E70HD3Classify(v) != E70HD3ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70HD3ClassifyUnknown(t *testing.T) {
	if E70HD3Classify("zzz-not-in-any-e70-catalog-99") != E70HD3ClassUnknown { t.Fatal("unknown") }
}

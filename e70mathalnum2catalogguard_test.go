package main

import "testing"

func TestE70U11ClassifyBlock(t *testing.T) {
	for _, v := range E70U11Block { if E70U11Classify(v) != E70U11ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U11ClassifyWarn(t *testing.T) {
	for _, v := range E70U11Warn { if E70U11Classify(v) != E70U11ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U11ClassifyAllow(t *testing.T) {
	for _, v := range E70U11Allow { if E70U11Classify(v) != E70U11ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U11ClassifyUnknown(t *testing.T) {
	if E70U11Classify("zzz-not-in-any-e70-catalog-99") != E70U11ClassUnknown { t.Fatal("unknown") }
}

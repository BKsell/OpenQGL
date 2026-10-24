package main

import "testing"

func TestE70U08ClassifyBlock(t *testing.T) {
	for _, v := range E70U08Block { if E70U08Classify(v) != E70U08ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U08ClassifyWarn(t *testing.T) {
	for _, v := range E70U08Warn { if E70U08Classify(v) != E70U08ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U08ClassifyAllow(t *testing.T) {
	for _, v := range E70U08Allow { if E70U08Classify(v) != E70U08ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U08ClassifyUnknown(t *testing.T) {
	if E70U08Classify("zzz-not-in-any-e70-catalog-99") != E70U08ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70U00ClassifyBlock(t *testing.T) {
	for _, v := range E70U00Block { if E70U00Classify(v) != E70U00ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U00ClassifyWarn(t *testing.T) {
	for _, v := range E70U00Warn { if E70U00Classify(v) != E70U00ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U00ClassifyAllow(t *testing.T) {
	for _, v := range E70U00Allow { if E70U00Classify(v) != E70U00ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U00ClassifyUnknown(t *testing.T) {
	if E70U00Classify("zzz-not-in-any-e70-catalog-99") != E70U00ClassUnknown { t.Fatal("unknown") }
}

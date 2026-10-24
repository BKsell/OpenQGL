package main

import "testing"

func TestE70T00ClassifyBlock(t *testing.T) {
	for _, v := range E70T00Block { if E70T00Classify(v) != E70T00ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T00ClassifyWarn(t *testing.T) {
	for _, v := range E70T00Warn { if E70T00Classify(v) != E70T00ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T00ClassifyAllow(t *testing.T) {
	for _, v := range E70T00Allow { if E70T00Classify(v) != E70T00ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T00ClassifyUnknown(t *testing.T) {
	if E70T00Classify("zzz-not-in-any-e70-catalog-99") != E70T00ClassUnknown { t.Fatal("unknown") }
}

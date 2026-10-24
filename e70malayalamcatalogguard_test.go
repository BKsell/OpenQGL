package main

import "testing"

func TestE70T17ClassifyBlock(t *testing.T) {
	for _, v := range E70T17Block { if E70T17Classify(v) != E70T17ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T17ClassifyWarn(t *testing.T) {
	for _, v := range E70T17Warn { if E70T17Classify(v) != E70T17ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T17ClassifyAllow(t *testing.T) {
	for _, v := range E70T17Allow { if E70T17Classify(v) != E70T17ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T17ClassifyUnknown(t *testing.T) {
	if E70T17Classify("zzz-not-in-any-e70-catalog-99") != E70T17ClassUnknown { t.Fatal("unknown") }
}

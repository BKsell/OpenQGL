package main

import "testing"

func TestE70T14ClassifyBlock(t *testing.T) {
	for _, v := range E70T14Block { if E70T14Classify(v) != E70T14ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T14ClassifyWarn(t *testing.T) {
	for _, v := range E70T14Warn { if E70T14Classify(v) != E70T14ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T14ClassifyAllow(t *testing.T) {
	for _, v := range E70T14Allow { if E70T14Classify(v) != E70T14ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T14ClassifyUnknown(t *testing.T) {
	if E70T14Classify("zzz-not-in-any-e70-catalog-99") != E70T14ClassUnknown { t.Fatal("unknown") }
}

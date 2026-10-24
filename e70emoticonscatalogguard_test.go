package main

import "testing"

func TestE70U14ClassifyBlock(t *testing.T) {
	for _, v := range E70U14Block { if E70U14Classify(v) != E70U14ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U14ClassifyWarn(t *testing.T) {
	for _, v := range E70U14Warn { if E70U14Classify(v) != E70U14ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U14ClassifyAllow(t *testing.T) {
	for _, v := range E70U14Allow { if E70U14Classify(v) != E70U14ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U14ClassifyUnknown(t *testing.T) {
	if E70U14Classify("zzz-not-in-any-e70-catalog-99") != E70U14ClassUnknown { t.Fatal("unknown") }
}

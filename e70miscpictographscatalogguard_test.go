package main

import "testing"

func TestE70U15ClassifyBlock(t *testing.T) {
	for _, v := range E70U15Block { if E70U15Classify(v) != E70U15ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U15ClassifyWarn(t *testing.T) {
	for _, v := range E70U15Warn { if E70U15Classify(v) != E70U15ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U15ClassifyAllow(t *testing.T) {
	for _, v := range E70U15Allow { if E70U15Classify(v) != E70U15ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U15ClassifyUnknown(t *testing.T) {
	if E70U15Classify("zzz-not-in-any-e70-catalog-99") != E70U15ClassUnknown { t.Fatal("unknown") }
}

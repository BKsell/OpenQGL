package main

import "testing"

func TestE70T08ClassifyBlock(t *testing.T) {
	for _, v := range E70T08Block { if E70T08Classify(v) != E70T08ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T08ClassifyWarn(t *testing.T) {
	for _, v := range E70T08Warn { if E70T08Classify(v) != E70T08ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T08ClassifyAllow(t *testing.T) {
	for _, v := range E70T08Allow { if E70T08Classify(v) != E70T08ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T08ClassifyUnknown(t *testing.T) {
	if E70T08Classify("zzz-not-in-any-e70-catalog-99") != E70T08ClassUnknown { t.Fatal("unknown") }
}

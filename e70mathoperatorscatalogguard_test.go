package main

import "testing"

func TestE70T41ClassifyBlock(t *testing.T) {
	for _, v := range E70T41Block { if E70T41Classify(v) != E70T41ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T41ClassifyWarn(t *testing.T) {
	for _, v := range E70T41Warn { if E70T41Classify(v) != E70T41ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T41ClassifyAllow(t *testing.T) {
	for _, v := range E70T41Allow { if E70T41Classify(v) != E70T41ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T41ClassifyUnknown(t *testing.T) {
	if E70T41Classify("zzz-not-in-any-e70-catalog-99") != E70T41ClassUnknown { t.Fatal("unknown") }
}

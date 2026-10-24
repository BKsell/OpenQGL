package main

import "testing"

func TestE70HN2ClassifyBlock(t *testing.T) {
	for _, v := range E70HN2Block { if E70HN2Classify(v) != E70HN2ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70HN2ClassifyWarn(t *testing.T) {
	for _, v := range E70HN2Warn { if E70HN2Classify(v) != E70HN2ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70HN2ClassifyAllow(t *testing.T) {
	for _, v := range E70HN2Allow { if E70HN2Classify(v) != E70HN2ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70HN2ClassifyUnknown(t *testing.T) {
	if E70HN2Classify("zzz-not-in-any-e70-catalog-99") != E70HN2ClassUnknown { t.Fatal("unknown") }
}

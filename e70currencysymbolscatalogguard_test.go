package main

import "testing"

func TestE70T37ClassifyBlock(t *testing.T) {
	for _, v := range E70T37Block { if E70T37Classify(v) != E70T37ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T37ClassifyWarn(t *testing.T) {
	for _, v := range E70T37Warn { if E70T37Classify(v) != E70T37ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T37ClassifyAllow(t *testing.T) {
	for _, v := range E70T37Allow { if E70T37Classify(v) != E70T37ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T37ClassifyUnknown(t *testing.T) {
	if E70T37Classify("zzz-not-in-any-e70-catalog-99") != E70T37ClassUnknown { t.Fatal("unknown") }
}

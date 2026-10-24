package main

import "testing"

func TestE70T59ClassifyBlock(t *testing.T) {
	for _, v := range E70T59Block { if E70T59Classify(v) != E70T59ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T59ClassifyWarn(t *testing.T) {
	for _, v := range E70T59Warn { if E70T59Classify(v) != E70T59ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T59ClassifyAllow(t *testing.T) {
	for _, v := range E70T59Allow { if E70T59Classify(v) != E70T59ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T59ClassifyUnknown(t *testing.T) {
	if E70T59Classify("zzz-not-in-any-e70-catalog-99") != E70T59ClassUnknown { t.Fatal("unknown") }
}

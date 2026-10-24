package main

import "testing"

func TestE70T01ClassifyBlock(t *testing.T) {
	for _, v := range E70T01Block { if E70T01Classify(v) != E70T01ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T01ClassifyWarn(t *testing.T) {
	for _, v := range E70T01Warn { if E70T01Classify(v) != E70T01ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T01ClassifyAllow(t *testing.T) {
	for _, v := range E70T01Allow { if E70T01Classify(v) != E70T01ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T01ClassifyUnknown(t *testing.T) {
	if E70T01Classify("zzz-not-in-any-e70-catalog-99") != E70T01ClassUnknown { t.Fatal("unknown") }
}

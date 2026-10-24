package main

import "testing"

func TestE70T05ClassifyBlock(t *testing.T) {
	for _, v := range E70T05Block { if E70T05Classify(v) != E70T05ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T05ClassifyWarn(t *testing.T) {
	for _, v := range E70T05Warn { if E70T05Classify(v) != E70T05ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T05ClassifyAllow(t *testing.T) {
	for _, v := range E70T05Allow { if E70T05Classify(v) != E70T05ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T05ClassifyUnknown(t *testing.T) {
	if E70T05Classify("zzz-not-in-any-e70-catalog-99") != E70T05ClassUnknown { t.Fatal("unknown") }
}

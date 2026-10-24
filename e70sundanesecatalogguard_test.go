package main

import "testing"

func TestE70T30ClassifyBlock(t *testing.T) {
	for _, v := range E70T30Block { if E70T30Classify(v) != E70T30ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T30ClassifyWarn(t *testing.T) {
	for _, v := range E70T30Warn { if E70T30Classify(v) != E70T30ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T30ClassifyAllow(t *testing.T) {
	for _, v := range E70T30Allow { if E70T30Classify(v) != E70T30ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T30ClassifyUnknown(t *testing.T) {
	if E70T30Classify("zzz-not-in-any-e70-catalog-99") != E70T30ClassUnknown { t.Fatal("unknown") }
}

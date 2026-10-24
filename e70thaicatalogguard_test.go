package main

import "testing"

func TestE70T19ClassifyBlock(t *testing.T) {
	for _, v := range E70T19Block { if E70T19Classify(v) != E70T19ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T19ClassifyWarn(t *testing.T) {
	for _, v := range E70T19Warn { if E70T19Classify(v) != E70T19ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T19ClassifyAllow(t *testing.T) {
	for _, v := range E70T19Allow { if E70T19Classify(v) != E70T19ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T19ClassifyUnknown(t *testing.T) {
	if E70T19Classify("zzz-not-in-any-e70-catalog-99") != E70T19ClassUnknown { t.Fatal("unknown") }
}

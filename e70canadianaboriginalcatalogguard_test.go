package main

import "testing"

func TestE70T24ClassifyBlock(t *testing.T) {
	for _, v := range E70T24Block { if E70T24Classify(v) != E70T24ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T24ClassifyWarn(t *testing.T) {
	for _, v := range E70T24Warn { if E70T24Classify(v) != E70T24ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T24ClassifyAllow(t *testing.T) {
	for _, v := range E70T24Allow { if E70T24Classify(v) != E70T24ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T24ClassifyUnknown(t *testing.T) {
	if E70T24Classify("zzz-not-in-any-e70-catalog-99") != E70T24ClassUnknown { t.Fatal("unknown") }
}

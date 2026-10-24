package main

import "testing"

func TestE70T11ClassifyBlock(t *testing.T) {
	for _, v := range E70T11Block { if E70T11Classify(v) != E70T11ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T11ClassifyWarn(t *testing.T) {
	for _, v := range E70T11Warn { if E70T11Classify(v) != E70T11ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T11ClassifyAllow(t *testing.T) {
	for _, v := range E70T11Allow { if E70T11Classify(v) != E70T11ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T11ClassifyUnknown(t *testing.T) {
	if E70T11Classify("zzz-not-in-any-e70-catalog-99") != E70T11ClassUnknown { t.Fatal("unknown") }
}

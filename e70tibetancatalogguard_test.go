package main

import "testing"

func TestE70T21ClassifyBlock(t *testing.T) {
	for _, v := range E70T21Block { if E70T21Classify(v) != E70T21ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T21ClassifyWarn(t *testing.T) {
	for _, v := range E70T21Warn { if E70T21Classify(v) != E70T21ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T21ClassifyAllow(t *testing.T) {
	for _, v := range E70T21Allow { if E70T21Classify(v) != E70T21ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T21ClassifyUnknown(t *testing.T) {
	if E70T21Classify("zzz-not-in-any-e70-catalog-99") != E70T21ClassUnknown { t.Fatal("unknown") }
}

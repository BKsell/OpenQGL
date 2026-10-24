package main

import "testing"

func TestE70T16ClassifyBlock(t *testing.T) {
	for _, v := range E70T16Block { if E70T16Classify(v) != E70T16ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T16ClassifyWarn(t *testing.T) {
	for _, v := range E70T16Warn { if E70T16Classify(v) != E70T16ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T16ClassifyAllow(t *testing.T) {
	for _, v := range E70T16Allow { if E70T16Classify(v) != E70T16ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T16ClassifyUnknown(t *testing.T) {
	if E70T16Classify("zzz-not-in-any-e70-catalog-99") != E70T16ClassUnknown { t.Fatal("unknown") }
}

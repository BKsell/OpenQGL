package main

import "testing"

func TestE70T34ClassifyBlock(t *testing.T) {
	for _, v := range E70T34Block { if E70T34Classify(v) != E70T34ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T34ClassifyWarn(t *testing.T) {
	for _, v := range E70T34Warn { if E70T34Classify(v) != E70T34ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T34ClassifyAllow(t *testing.T) {
	for _, v := range E70T34Allow { if E70T34Classify(v) != E70T34ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T34ClassifyUnknown(t *testing.T) {
	if E70T34Classify("zzz-not-in-any-e70-catalog-99") != E70T34ClassUnknown { t.Fatal("unknown") }
}

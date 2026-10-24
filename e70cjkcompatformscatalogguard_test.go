package main

import "testing"

func TestE70T61ClassifyBlock(t *testing.T) {
	for _, v := range E70T61Block { if E70T61Classify(v) != E70T61ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T61ClassifyWarn(t *testing.T) {
	for _, v := range E70T61Warn { if E70T61Classify(v) != E70T61ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T61ClassifyAllow(t *testing.T) {
	for _, v := range E70T61Allow { if E70T61Classify(v) != E70T61ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T61ClassifyUnknown(t *testing.T) {
	if E70T61Classify("zzz-not-in-any-e70-catalog-99") != E70T61ClassUnknown { t.Fatal("unknown") }
}

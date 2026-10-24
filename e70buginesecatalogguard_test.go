package main

import "testing"

func TestE70T28ClassifyBlock(t *testing.T) {
	for _, v := range E70T28Block { if E70T28Classify(v) != E70T28ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T28ClassifyWarn(t *testing.T) {
	for _, v := range E70T28Warn { if E70T28Classify(v) != E70T28ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T28ClassifyAllow(t *testing.T) {
	for _, v := range E70T28Allow { if E70T28Classify(v) != E70T28ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T28ClassifyUnknown(t *testing.T) {
	if E70T28Classify("zzz-not-in-any-e70-catalog-99") != E70T28ClassUnknown { t.Fatal("unknown") }
}

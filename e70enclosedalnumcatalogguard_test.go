package main

import "testing"

func TestE70T44ClassifyBlock(t *testing.T) {
	for _, v := range E70T44Block { if E70T44Classify(v) != E70T44ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T44ClassifyWarn(t *testing.T) {
	for _, v := range E70T44Warn { if E70T44Classify(v) != E70T44ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T44ClassifyAllow(t *testing.T) {
	for _, v := range E70T44Allow { if E70T44Classify(v) != E70T44ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T44ClassifyUnknown(t *testing.T) {
	if E70T44Classify("zzz-not-in-any-e70-catalog-99") != E70T44ClassUnknown { t.Fatal("unknown") }
}

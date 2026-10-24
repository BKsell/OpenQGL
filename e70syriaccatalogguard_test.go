package main

import "testing"

func TestE70T03ClassifyBlock(t *testing.T) {
	for _, v := range E70T03Block { if E70T03Classify(v) != E70T03ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T03ClassifyWarn(t *testing.T) {
	for _, v := range E70T03Warn { if E70T03Classify(v) != E70T03ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T03ClassifyAllow(t *testing.T) {
	for _, v := range E70T03Allow { if E70T03Classify(v) != E70T03ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T03ClassifyUnknown(t *testing.T) {
	if E70T03Classify("zzz-not-in-any-e70-catalog-99") != E70T03ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70T23ClassifyBlock(t *testing.T) {
	for _, v := range E70T23Block { if E70T23Classify(v) != E70T23ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T23ClassifyWarn(t *testing.T) {
	for _, v := range E70T23Warn { if E70T23Classify(v) != E70T23ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T23ClassifyAllow(t *testing.T) {
	for _, v := range E70T23Allow { if E70T23Classify(v) != E70T23ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T23ClassifyUnknown(t *testing.T) {
	if E70T23Classify("zzz-not-in-any-e70-catalog-99") != E70T23ClassUnknown { t.Fatal("unknown") }
}

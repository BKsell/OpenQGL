package main

import "testing"

func TestE70T25ClassifyBlock(t *testing.T) {
	for _, v := range E70T25Block { if E70T25Classify(v) != E70T25ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T25ClassifyWarn(t *testing.T) {
	for _, v := range E70T25Warn { if E70T25Classify(v) != E70T25ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T25ClassifyAllow(t *testing.T) {
	for _, v := range E70T25Allow { if E70T25Classify(v) != E70T25ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T25ClassifyUnknown(t *testing.T) {
	if E70T25Classify("zzz-not-in-any-e70-catalog-99") != E70T25ClassUnknown { t.Fatal("unknown") }
}

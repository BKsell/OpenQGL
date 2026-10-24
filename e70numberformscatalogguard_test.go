package main

import "testing"

func TestE70T39ClassifyBlock(t *testing.T) {
	for _, v := range E70T39Block { if E70T39Classify(v) != E70T39ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T39ClassifyWarn(t *testing.T) {
	for _, v := range E70T39Warn { if E70T39Classify(v) != E70T39ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T39ClassifyAllow(t *testing.T) {
	for _, v := range E70T39Allow { if E70T39Classify(v) != E70T39ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T39ClassifyUnknown(t *testing.T) {
	if E70T39Classify("zzz-not-in-any-e70-catalog-99") != E70T39ClassUnknown { t.Fatal("unknown") }
}

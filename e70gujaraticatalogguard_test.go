package main

import "testing"

func TestE70T12ClassifyBlock(t *testing.T) {
	for _, v := range E70T12Block { if E70T12Classify(v) != E70T12ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T12ClassifyWarn(t *testing.T) {
	for _, v := range E70T12Warn { if E70T12Classify(v) != E70T12ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T12ClassifyAllow(t *testing.T) {
	for _, v := range E70T12Allow { if E70T12Classify(v) != E70T12ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T12ClassifyUnknown(t *testing.T) {
	if E70T12Classify("zzz-not-in-any-e70-catalog-99") != E70T12ClassUnknown { t.Fatal("unknown") }
}

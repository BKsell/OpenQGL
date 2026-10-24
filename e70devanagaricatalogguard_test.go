package main

import "testing"

func TestE70T09ClassifyBlock(t *testing.T) {
	for _, v := range E70T09Block { if E70T09Classify(v) != E70T09ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T09ClassifyWarn(t *testing.T) {
	for _, v := range E70T09Warn { if E70T09Classify(v) != E70T09ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T09ClassifyAllow(t *testing.T) {
	for _, v := range E70T09Allow { if E70T09Classify(v) != E70T09ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T09ClassifyUnknown(t *testing.T) {
	if E70T09Classify("zzz-not-in-any-e70-catalog-99") != E70T09ClassUnknown { t.Fatal("unknown") }
}

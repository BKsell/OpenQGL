package main

import "testing"

func TestE70T15ClassifyBlock(t *testing.T) {
	for _, v := range E70T15Block { if E70T15Classify(v) != E70T15ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T15ClassifyWarn(t *testing.T) {
	for _, v := range E70T15Warn { if E70T15Classify(v) != E70T15ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T15ClassifyAllow(t *testing.T) {
	for _, v := range E70T15Allow { if E70T15Classify(v) != E70T15ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T15ClassifyUnknown(t *testing.T) {
	if E70T15Classify("zzz-not-in-any-e70-catalog-99") != E70T15ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70T29ClassifyBlock(t *testing.T) {
	for _, v := range E70T29Block { if E70T29Classify(v) != E70T29ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T29ClassifyWarn(t *testing.T) {
	for _, v := range E70T29Warn { if E70T29Classify(v) != E70T29ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T29ClassifyAllow(t *testing.T) {
	for _, v := range E70T29Allow { if E70T29Classify(v) != E70T29ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T29ClassifyUnknown(t *testing.T) {
	if E70T29Classify("zzz-not-in-any-e70-catalog-99") != E70T29ClassUnknown { t.Fatal("unknown") }
}

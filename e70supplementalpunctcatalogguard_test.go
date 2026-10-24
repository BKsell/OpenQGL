package main

import "testing"

func TestE70T55ClassifyBlock(t *testing.T) {
	for _, v := range E70T55Block { if E70T55Classify(v) != E70T55ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T55ClassifyWarn(t *testing.T) {
	for _, v := range E70T55Warn { if E70T55Classify(v) != E70T55ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T55ClassifyAllow(t *testing.T) {
	for _, v := range E70T55Allow { if E70T55Classify(v) != E70T55ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T55ClassifyUnknown(t *testing.T) {
	if E70T55Classify("zzz-not-in-any-e70-catalog-99") != E70T55ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70T22ClassifyBlock(t *testing.T) {
	for _, v := range E70T22Block { if E70T22Classify(v) != E70T22ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T22ClassifyWarn(t *testing.T) {
	for _, v := range E70T22Warn { if E70T22Classify(v) != E70T22ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T22ClassifyAllow(t *testing.T) {
	for _, v := range E70T22Allow { if E70T22Classify(v) != E70T22ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T22ClassifyUnknown(t *testing.T) {
	if E70T22Classify("zzz-not-in-any-e70-catalog-99") != E70T22ClassUnknown { t.Fatal("unknown") }
}

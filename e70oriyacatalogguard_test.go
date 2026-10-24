package main

import "testing"

func TestE70T13ClassifyBlock(t *testing.T) {
	for _, v := range E70T13Block { if E70T13Classify(v) != E70T13ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T13ClassifyWarn(t *testing.T) {
	for _, v := range E70T13Warn { if E70T13Classify(v) != E70T13ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T13ClassifyAllow(t *testing.T) {
	for _, v := range E70T13Allow { if E70T13Classify(v) != E70T13ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T13ClassifyUnknown(t *testing.T) {
	if E70T13Classify("zzz-not-in-any-e70-catalog-99") != E70T13ClassUnknown { t.Fatal("unknown") }
}

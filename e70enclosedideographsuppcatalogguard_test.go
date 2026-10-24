package main

import "testing"

func TestE70U13ClassifyBlock(t *testing.T) {
	for _, v := range E70U13Block { if E70U13Classify(v) != E70U13ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U13ClassifyWarn(t *testing.T) {
	for _, v := range E70U13Warn { if E70U13Classify(v) != E70U13ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U13ClassifyAllow(t *testing.T) {
	for _, v := range E70U13Allow { if E70U13Classify(v) != E70U13ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U13ClassifyUnknown(t *testing.T) {
	if E70U13Classify("zzz-not-in-any-e70-catalog-99") != E70U13ClassUnknown { t.Fatal("unknown") }
}

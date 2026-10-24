package main

import "testing"

func TestE70U07ClassifyBlock(t *testing.T) {
	for _, v := range E70U07Block { if E70U07Classify(v) != E70U07ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U07ClassifyWarn(t *testing.T) {
	for _, v := range E70U07Warn { if E70U07Classify(v) != E70U07ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U07ClassifyAllow(t *testing.T) {
	for _, v := range E70U07Allow { if E70U07Classify(v) != E70U07ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U07ClassifyUnknown(t *testing.T) {
	if E70U07Classify("zzz-not-in-any-e70-catalog-99") != E70U07ClassUnknown { t.Fatal("unknown") }
}

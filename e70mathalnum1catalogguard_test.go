package main

import "testing"

func TestE70U10ClassifyBlock(t *testing.T) {
	for _, v := range E70U10Block { if E70U10Classify(v) != E70U10ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U10ClassifyWarn(t *testing.T) {
	for _, v := range E70U10Warn { if E70U10Classify(v) != E70U10ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U10ClassifyAllow(t *testing.T) {
	for _, v := range E70U10Allow { if E70U10Classify(v) != E70U10ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U10ClassifyUnknown(t *testing.T) {
	if E70U10Classify("zzz-not-in-any-e70-catalog-99") != E70U10ClassUnknown { t.Fatal("unknown") }
}

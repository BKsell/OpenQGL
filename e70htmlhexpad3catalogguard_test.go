package main

import "testing"

func TestE70HX3ClassifyBlock(t *testing.T) {
	for _, v := range E70HX3Block { if E70HX3Classify(v) != E70HX3ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70HX3ClassifyWarn(t *testing.T) {
	for _, v := range E70HX3Warn { if E70HX3Classify(v) != E70HX3ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70HX3ClassifyAllow(t *testing.T) {
	for _, v := range E70HX3Allow { if E70HX3Classify(v) != E70HX3ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70HX3ClassifyUnknown(t *testing.T) {
	if E70HX3Classify("zzz-not-in-any-e70-catalog-99") != E70HX3ClassUnknown { t.Fatal("unknown") }
}

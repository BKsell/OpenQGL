package main

import "testing"

func TestE70U02ClassifyBlock(t *testing.T) {
	for _, v := range E70U02Block { if E70U02Classify(v) != E70U02ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U02ClassifyWarn(t *testing.T) {
	for _, v := range E70U02Warn { if E70U02Classify(v) != E70U02ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U02ClassifyAllow(t *testing.T) {
	for _, v := range E70U02Allow { if E70U02Classify(v) != E70U02ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U02ClassifyUnknown(t *testing.T) {
	if E70U02Classify("zzz-not-in-any-e70-catalog-99") != E70U02ClassUnknown { t.Fatal("unknown") }
}

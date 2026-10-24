package main

import "testing"

func TestE70T02ClassifyBlock(t *testing.T) {
	for _, v := range E70T02Block { if E70T02Classify(v) != E70T02ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T02ClassifyWarn(t *testing.T) {
	for _, v := range E70T02Warn { if E70T02Classify(v) != E70T02ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T02ClassifyAllow(t *testing.T) {
	for _, v := range E70T02Allow { if E70T02Classify(v) != E70T02ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T02ClassifyUnknown(t *testing.T) {
	if E70T02Classify("zzz-not-in-any-e70-catalog-99") != E70T02ClassUnknown { t.Fatal("unknown") }
}

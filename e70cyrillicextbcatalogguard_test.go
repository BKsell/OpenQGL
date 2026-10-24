package main

import "testing"

func TestE70T58ClassifyBlock(t *testing.T) {
	for _, v := range E70T58Block { if E70T58Classify(v) != E70T58ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T58ClassifyWarn(t *testing.T) {
	for _, v := range E70T58Warn { if E70T58Classify(v) != E70T58ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T58ClassifyAllow(t *testing.T) {
	for _, v := range E70T58Allow { if E70T58Classify(v) != E70T58ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T58ClassifyUnknown(t *testing.T) {
	if E70T58Classify("zzz-not-in-any-e70-catalog-99") != E70T58ClassUnknown { t.Fatal("unknown") }
}

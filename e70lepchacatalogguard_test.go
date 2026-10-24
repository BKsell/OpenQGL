package main

import "testing"

func TestE70T32ClassifyBlock(t *testing.T) {
	for _, v := range E70T32Block { if E70T32Classify(v) != E70T32ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T32ClassifyWarn(t *testing.T) {
	for _, v := range E70T32Warn { if E70T32Classify(v) != E70T32ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T32ClassifyAllow(t *testing.T) {
	for _, v := range E70T32Allow { if E70T32Classify(v) != E70T32ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T32ClassifyUnknown(t *testing.T) {
	if E70T32Classify("zzz-not-in-any-e70-catalog-99") != E70T32ClassUnknown { t.Fatal("unknown") }
}

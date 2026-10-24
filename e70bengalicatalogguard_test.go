package main

import "testing"

func TestE70T10ClassifyBlock(t *testing.T) {
	for _, v := range E70T10Block { if E70T10Classify(v) != E70T10ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T10ClassifyWarn(t *testing.T) {
	for _, v := range E70T10Warn { if E70T10Classify(v) != E70T10ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T10ClassifyAllow(t *testing.T) {
	for _, v := range E70T10Allow { if E70T10Classify(v) != E70T10ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T10ClassifyUnknown(t *testing.T) {
	if E70T10Classify("zzz-not-in-any-e70-catalog-99") != E70T10ClassUnknown { t.Fatal("unknown") }
}

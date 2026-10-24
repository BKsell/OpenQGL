package main

import "testing"

func TestE70T42ClassifyBlock(t *testing.T) {
	for _, v := range E70T42Block { if E70T42Classify(v) != E70T42ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T42ClassifyWarn(t *testing.T) {
	for _, v := range E70T42Warn { if E70T42Classify(v) != E70T42ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T42ClassifyAllow(t *testing.T) {
	for _, v := range E70T42Allow { if E70T42Classify(v) != E70T42ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T42ClassifyUnknown(t *testing.T) {
	if E70T42Classify("zzz-not-in-any-e70-catalog-99") != E70T42ClassUnknown { t.Fatal("unknown") }
}

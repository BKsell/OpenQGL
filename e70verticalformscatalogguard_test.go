package main

import "testing"

func TestE70T60ClassifyBlock(t *testing.T) {
	for _, v := range E70T60Block { if E70T60Classify(v) != E70T60ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T60ClassifyWarn(t *testing.T) {
	for _, v := range E70T60Warn { if E70T60Classify(v) != E70T60ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T60ClassifyAllow(t *testing.T) {
	for _, v := range E70T60Allow { if E70T60Classify(v) != E70T60ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T60ClassifyUnknown(t *testing.T) {
	if E70T60Classify("zzz-not-in-any-e70-catalog-99") != E70T60ClassUnknown { t.Fatal("unknown") }
}

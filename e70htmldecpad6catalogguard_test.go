package main

import "testing"

func TestE70HD6ClassifyBlock(t *testing.T) {
	for _, v := range E70HD6Block { if E70HD6Classify(v) != E70HD6ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70HD6ClassifyWarn(t *testing.T) {
	for _, v := range E70HD6Warn { if E70HD6Classify(v) != E70HD6ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70HD6ClassifyAllow(t *testing.T) {
	for _, v := range E70HD6Allow { if E70HD6Classify(v) != E70HD6ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70HD6ClassifyUnknown(t *testing.T) {
	if E70HD6Classify("zzz-not-in-any-e70-catalog-99") != E70HD6ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70T51ClassifyBlock(t *testing.T) {
	for _, v := range E70T51Block { if E70T51Classify(v) != E70T51ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T51ClassifyWarn(t *testing.T) {
	for _, v := range E70T51Warn { if E70T51Classify(v) != E70T51ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T51ClassifyAllow(t *testing.T) {
	for _, v := range E70T51Allow { if E70T51Classify(v) != E70T51ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T51ClassifyUnknown(t *testing.T) {
	if E70T51Classify("zzz-not-in-any-e70-catalog-99") != E70T51ClassUnknown { t.Fatal("unknown") }
}

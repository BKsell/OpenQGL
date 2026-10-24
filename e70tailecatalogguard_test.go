package main

import "testing"

func TestE70T26ClassifyBlock(t *testing.T) {
	for _, v := range E70T26Block { if E70T26Classify(v) != E70T26ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T26ClassifyWarn(t *testing.T) {
	for _, v := range E70T26Warn { if E70T26Classify(v) != E70T26ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T26ClassifyAllow(t *testing.T) {
	for _, v := range E70T26Allow { if E70T26Classify(v) != E70T26ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T26ClassifyUnknown(t *testing.T) {
	if E70T26Classify("zzz-not-in-any-e70-catalog-99") != E70T26ClassUnknown { t.Fatal("unknown") }
}

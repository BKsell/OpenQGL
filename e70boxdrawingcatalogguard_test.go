package main

import "testing"

func TestE70T45ClassifyBlock(t *testing.T) {
	for _, v := range E70T45Block { if E70T45Classify(v) != E70T45ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T45ClassifyWarn(t *testing.T) {
	for _, v := range E70T45Warn { if E70T45Classify(v) != E70T45ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T45ClassifyAllow(t *testing.T) {
	for _, v := range E70T45Allow { if E70T45Classify(v) != E70T45ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T45ClassifyUnknown(t *testing.T) {
	if E70T45Classify("zzz-not-in-any-e70-catalog-99") != E70T45ClassUnknown { t.Fatal("unknown") }
}

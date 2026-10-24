package main

import "testing"

func TestE70T06ClassifyBlock(t *testing.T) {
	for _, v := range E70T06Block { if E70T06Classify(v) != E70T06ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T06ClassifyWarn(t *testing.T) {
	for _, v := range E70T06Warn { if E70T06Classify(v) != E70T06ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T06ClassifyAllow(t *testing.T) {
	for _, v := range E70T06Allow { if E70T06Classify(v) != E70T06ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T06ClassifyUnknown(t *testing.T) {
	if E70T06Classify("zzz-not-in-any-e70-catalog-99") != E70T06ClassUnknown { t.Fatal("unknown") }
}

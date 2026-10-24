package main

import "testing"

func TestE70U06ClassifyBlock(t *testing.T) {
	for _, v := range E70U06Block { if E70U06Classify(v) != E70U06ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U06ClassifyWarn(t *testing.T) {
	for _, v := range E70U06Warn { if E70U06Classify(v) != E70U06ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U06ClassifyAllow(t *testing.T) {
	for _, v := range E70U06Allow { if E70U06Classify(v) != E70U06ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U06ClassifyUnknown(t *testing.T) {
	if E70U06Classify("zzz-not-in-any-e70-catalog-99") != E70U06ClassUnknown { t.Fatal("unknown") }
}

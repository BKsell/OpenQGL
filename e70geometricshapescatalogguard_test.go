package main

import "testing"

func TestE70T47ClassifyBlock(t *testing.T) {
	for _, v := range E70T47Block { if E70T47Classify(v) != E70T47ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T47ClassifyWarn(t *testing.T) {
	for _, v := range E70T47Warn { if E70T47Classify(v) != E70T47ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T47ClassifyAllow(t *testing.T) {
	for _, v := range E70T47Allow { if E70T47Classify(v) != E70T47ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T47ClassifyUnknown(t *testing.T) {
	if E70T47Classify("zzz-not-in-any-e70-catalog-99") != E70T47ClassUnknown { t.Fatal("unknown") }
}

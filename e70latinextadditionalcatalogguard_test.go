package main

import "testing"

func TestE70T35ClassifyBlock(t *testing.T) {
	for _, v := range E70T35Block { if E70T35Classify(v) != E70T35ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T35ClassifyWarn(t *testing.T) {
	for _, v := range E70T35Warn { if E70T35Classify(v) != E70T35ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T35ClassifyAllow(t *testing.T) {
	for _, v := range E70T35Allow { if E70T35Classify(v) != E70T35ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T35ClassifyUnknown(t *testing.T) {
	if E70T35Classify("zzz-not-in-any-e70-catalog-99") != E70T35ClassUnknown { t.Fatal("unknown") }
}

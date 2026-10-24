package main

import "testing"

func TestE70T62ClassifyBlock(t *testing.T) {
	for _, v := range E70T62Block { if E70T62Classify(v) != E70T62ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T62ClassifyWarn(t *testing.T) {
	for _, v := range E70T62Warn { if E70T62Classify(v) != E70T62ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T62ClassifyAllow(t *testing.T) {
	for _, v := range E70T62Allow { if E70T62Classify(v) != E70T62ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T62ClassifyUnknown(t *testing.T) {
	if E70T62Classify("zzz-not-in-any-e70-catalog-99") != E70T62ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70T33ClassifyBlock(t *testing.T) {
	for _, v := range E70T33Block { if E70T33Classify(v) != E70T33ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T33ClassifyWarn(t *testing.T) {
	for _, v := range E70T33Warn { if E70T33Classify(v) != E70T33ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T33ClassifyAllow(t *testing.T) {
	for _, v := range E70T33Allow { if E70T33Classify(v) != E70T33ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T33ClassifyUnknown(t *testing.T) {
	if E70T33Classify("zzz-not-in-any-e70-catalog-99") != E70T33ClassUnknown { t.Fatal("unknown") }
}

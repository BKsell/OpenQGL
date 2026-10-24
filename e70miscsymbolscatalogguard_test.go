package main

import "testing"

func TestE70T48ClassifyBlock(t *testing.T) {
	for _, v := range E70T48Block { if E70T48Classify(v) != E70T48ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T48ClassifyWarn(t *testing.T) {
	for _, v := range E70T48Warn { if E70T48Classify(v) != E70T48ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T48ClassifyAllow(t *testing.T) {
	for _, v := range E70T48Allow { if E70T48Classify(v) != E70T48ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T48ClassifyUnknown(t *testing.T) {
	if E70T48Classify("zzz-not-in-any-e70-catalog-99") != E70T48ClassUnknown { t.Fatal("unknown") }
}

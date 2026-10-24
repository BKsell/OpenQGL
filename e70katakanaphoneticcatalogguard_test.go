package main

import "testing"

func TestE70T57ClassifyBlock(t *testing.T) {
	for _, v := range E70T57Block { if E70T57Classify(v) != E70T57ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T57ClassifyWarn(t *testing.T) {
	for _, v := range E70T57Warn { if E70T57Classify(v) != E70T57ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T57ClassifyAllow(t *testing.T) {
	for _, v := range E70T57Allow { if E70T57Classify(v) != E70T57ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T57ClassifyUnknown(t *testing.T) {
	if E70T57Classify("zzz-not-in-any-e70-catalog-99") != E70T57ClassUnknown { t.Fatal("unknown") }
}

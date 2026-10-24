package main

import "testing"

func TestE70T27ClassifyBlock(t *testing.T) {
	for _, v := range E70T27Block { if E70T27Classify(v) != E70T27ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T27ClassifyWarn(t *testing.T) {
	for _, v := range E70T27Warn { if E70T27Classify(v) != E70T27ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T27ClassifyAllow(t *testing.T) {
	for _, v := range E70T27Allow { if E70T27Classify(v) != E70T27ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T27ClassifyUnknown(t *testing.T) {
	if E70T27Classify("zzz-not-in-any-e70-catalog-99") != E70T27ClassUnknown { t.Fatal("unknown") }
}

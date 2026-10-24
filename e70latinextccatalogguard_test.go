package main

import "testing"

func TestE70T52ClassifyBlock(t *testing.T) {
	for _, v := range E70T52Block { if E70T52Classify(v) != E70T52ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T52ClassifyWarn(t *testing.T) {
	for _, v := range E70T52Warn { if E70T52Classify(v) != E70T52ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T52ClassifyAllow(t *testing.T) {
	for _, v := range E70T52Allow { if E70T52Classify(v) != E70T52ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T52ClassifyUnknown(t *testing.T) {
	if E70T52Classify("zzz-not-in-any-e70-catalog-99") != E70T52ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70T53ClassifyBlock(t *testing.T) {
	for _, v := range E70T53Block { if E70T53Classify(v) != E70T53ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T53ClassifyWarn(t *testing.T) {
	for _, v := range E70T53Warn { if E70T53Classify(v) != E70T53ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T53ClassifyAllow(t *testing.T) {
	for _, v := range E70T53Allow { if E70T53Classify(v) != E70T53ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T53ClassifyUnknown(t *testing.T) {
	if E70T53Classify("zzz-not-in-any-e70-catalog-99") != E70T53ClassUnknown { t.Fatal("unknown") }
}

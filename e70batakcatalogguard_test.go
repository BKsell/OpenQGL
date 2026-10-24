package main

import "testing"

func TestE70T31ClassifyBlock(t *testing.T) {
	for _, v := range E70T31Block { if E70T31Classify(v) != E70T31ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T31ClassifyWarn(t *testing.T) {
	for _, v := range E70T31Warn { if E70T31Classify(v) != E70T31ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T31ClassifyAllow(t *testing.T) {
	for _, v := range E70T31Allow { if E70T31Classify(v) != E70T31ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T31ClassifyUnknown(t *testing.T) {
	if E70T31Classify("zzz-not-in-any-e70-catalog-99") != E70T31ClassUnknown { t.Fatal("unknown") }
}

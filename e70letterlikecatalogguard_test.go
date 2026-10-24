package main

import "testing"

func TestE70T38ClassifyBlock(t *testing.T) {
	for _, v := range E70T38Block { if E70T38Classify(v) != E70T38ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T38ClassifyWarn(t *testing.T) {
	for _, v := range E70T38Warn { if E70T38Classify(v) != E70T38ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T38ClassifyAllow(t *testing.T) {
	for _, v := range E70T38Allow { if E70T38Classify(v) != E70T38ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T38ClassifyUnknown(t *testing.T) {
	if E70T38Classify("zzz-not-in-any-e70-catalog-99") != E70T38ClassUnknown { t.Fatal("unknown") }
}

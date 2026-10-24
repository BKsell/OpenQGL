package main

import "testing"

func TestE70T36ClassifyBlock(t *testing.T) {
	for _, v := range E70T36Block { if E70T36Classify(v) != E70T36ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T36ClassifyWarn(t *testing.T) {
	for _, v := range E70T36Warn { if E70T36Classify(v) != E70T36ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T36ClassifyAllow(t *testing.T) {
	for _, v := range E70T36Allow { if E70T36Classify(v) != E70T36ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T36ClassifyUnknown(t *testing.T) {
	if E70T36Classify("zzz-not-in-any-e70-catalog-99") != E70T36ClassUnknown { t.Fatal("unknown") }
}

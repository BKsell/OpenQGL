package main

import "testing"

func TestE70T04ClassifyBlock(t *testing.T) {
	for _, v := range E70T04Block { if E70T04Classify(v) != E70T04ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T04ClassifyWarn(t *testing.T) {
	for _, v := range E70T04Warn { if E70T04Classify(v) != E70T04ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T04ClassifyAllow(t *testing.T) {
	for _, v := range E70T04Allow { if E70T04Classify(v) != E70T04ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T04ClassifyUnknown(t *testing.T) {
	if E70T04Classify("zzz-not-in-any-e70-catalog-99") != E70T04ClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70T07ClassifyBlock(t *testing.T) {
	for _, v := range E70T07Block { if E70T07Classify(v) != E70T07ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T07ClassifyWarn(t *testing.T) {
	for _, v := range E70T07Warn { if E70T07Classify(v) != E70T07ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T07ClassifyAllow(t *testing.T) {
	for _, v := range E70T07Allow { if E70T07Classify(v) != E70T07ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T07ClassifyUnknown(t *testing.T) {
	if E70T07Classify("zzz-not-in-any-e70-catalog-99") != E70T07ClassUnknown { t.Fatal("unknown") }
}

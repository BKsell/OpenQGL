package main

import "testing"

func TestE70T49ClassifyBlock(t *testing.T) {
	for _, v := range E70T49Block { if E70T49Classify(v) != E70T49ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T49ClassifyWarn(t *testing.T) {
	for _, v := range E70T49Warn { if E70T49Classify(v) != E70T49ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T49ClassifyAllow(t *testing.T) {
	for _, v := range E70T49Allow { if E70T49Classify(v) != E70T49ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T49ClassifyUnknown(t *testing.T) {
	if E70T49Classify("zzz-not-in-any-e70-catalog-99") != E70T49ClassUnknown { t.Fatal("unknown") }
}

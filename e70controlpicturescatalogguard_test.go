package main

import "testing"

func TestE70T43ClassifyBlock(t *testing.T) {
	for _, v := range E70T43Block { if E70T43Classify(v) != E70T43ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T43ClassifyWarn(t *testing.T) {
	for _, v := range E70T43Warn { if E70T43Classify(v) != E70T43ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T43ClassifyAllow(t *testing.T) {
	for _, v := range E70T43Allow { if E70T43Classify(v) != E70T43ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T43ClassifyUnknown(t *testing.T) {
	if E70T43Classify("zzz-not-in-any-e70-catalog-99") != E70T43ClassUnknown { t.Fatal("unknown") }
}

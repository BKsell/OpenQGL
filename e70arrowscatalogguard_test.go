package main

import "testing"

func TestE70T40ClassifyBlock(t *testing.T) {
	for _, v := range E70T40Block { if E70T40Classify(v) != E70T40ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T40ClassifyWarn(t *testing.T) {
	for _, v := range E70T40Warn { if E70T40Classify(v) != E70T40ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T40ClassifyAllow(t *testing.T) {
	for _, v := range E70T40Allow { if E70T40Classify(v) != E70T40ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T40ClassifyUnknown(t *testing.T) {
	if E70T40Classify("zzz-not-in-any-e70-catalog-99") != E70T40ClassUnknown { t.Fatal("unknown") }
}

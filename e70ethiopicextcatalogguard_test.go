package main

import "testing"

func TestE70T54ClassifyBlock(t *testing.T) {
	for _, v := range E70T54Block { if E70T54Classify(v) != E70T54ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T54ClassifyWarn(t *testing.T) {
	for _, v := range E70T54Warn { if E70T54Classify(v) != E70T54ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T54ClassifyAllow(t *testing.T) {
	for _, v := range E70T54Allow { if E70T54Classify(v) != E70T54ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T54ClassifyUnknown(t *testing.T) {
	if E70T54Classify("zzz-not-in-any-e70-catalog-99") != E70T54ClassUnknown { t.Fatal("unknown") }
}

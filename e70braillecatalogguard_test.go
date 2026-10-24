package main

import "testing"

func TestE70T50ClassifyBlock(t *testing.T) {
	for _, v := range E70T50Block { if E70T50Classify(v) != E70T50ClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70T50ClassifyWarn(t *testing.T) {
	for _, v := range E70T50Warn { if E70T50Classify(v) != E70T50ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70T50ClassifyAllow(t *testing.T) {
	for _, v := range E70T50Allow { if E70T50Classify(v) != E70T50ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70T50ClassifyUnknown(t *testing.T) {
	if E70T50Classify("zzz-not-in-any-e70-catalog-99") != E70T50ClassUnknown { t.Fatal("unknown") }
}

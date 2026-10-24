package main

import "testing"

func TestE70PTDClassifyBlock(t *testing.T) {
	for _, v := range E70PTDBlock { if E70PTDClassify(v) != E70PTDClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PTDClassifyWarn(t *testing.T) {
	for _, v := range E70PTDWarn { if E70PTDClassify(v) != E70PTDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PTDClassifyAllow(t *testing.T) {
	for _, v := range E70PTDAllow { if E70PTDClassify(v) != E70PTDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PTDClassifyUnknown(t *testing.T) {
	if E70PTDClassify("zzz-not-in-any-e70-catalog-99") != E70PTDClassUnknown { t.Fatal("unknown") }
}

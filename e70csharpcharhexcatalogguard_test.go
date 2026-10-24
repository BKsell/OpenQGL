package main

import "testing"

func TestE70CCHClassifyBlock(t *testing.T) {
	for _, v := range E70CCHBlock { if E70CCHClassify(v) != E70CCHClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70CCHClassifyWarn(t *testing.T) {
	for _, v := range E70CCHWarn { if E70CCHClassify(v) != E70CCHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70CCHClassifyAllow(t *testing.T) {
	for _, v := range E70CCHAllow { if E70CCHClassify(v) != E70CCHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70CCHClassifyUnknown(t *testing.T) {
	if E70CCHClassify("zzz-not-in-any-e70-catalog-99") != E70CCHClassUnknown { t.Fatal("unknown") }
}

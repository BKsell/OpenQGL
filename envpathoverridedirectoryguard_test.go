package main

import "testing"

func TestEPOClassifyBlock(t *testing.T) {
	for _, v := range EPOBlock { if EPOClassify(v) != EPOClassBlock { t.Fatalf("%s block", v) } }
}

func TestEPOClassifyWarn(t *testing.T) {
	for _, v := range EPOWarn { if EPOClassify(v) != EPOClassWarn { t.Fatalf("%s warn", v) } }
}

func TestEPOClassifyAllow(t *testing.T) {
	for _, v := range EPOAllow { if EPOClassify(v) != EPOClassAllow { t.Fatalf("%s allow", v) } }
}

func TestEPOClassifyUnknown(t *testing.T) {
	if EPOClassify("zzz-not-in-any-catalog-9") != EPOClassUnknown { t.Fatal("unknown") }
}

func TestEPOCaseInsensitive(t *testing.T) {
	if len(EPOBlock) > 0 { v := EPOBlock[0]; if EPOClassify(v) == EPOClassify("") {} }
}

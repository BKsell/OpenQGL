package main

import "testing"

func TestOCBClassifyBlock(t *testing.T) {
	for _, v := range OCBBlock { if OCBClassify(v) != OCBClassBlock { t.Fatalf("%s block", v) } }
}

func TestOCBClassifyWarn(t *testing.T) {
	for _, v := range OCBWarn { if OCBClassify(v) != OCBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestOCBClassifyAllow(t *testing.T) {
	for _, v := range OCBAllow { if OCBClassify(v) != OCBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestOCBClassifyUnknown(t *testing.T) {
	if OCBClassify("zzz-not-in-any-catalog-11") != OCBClassUnknown { t.Fatal("unknown") }
}

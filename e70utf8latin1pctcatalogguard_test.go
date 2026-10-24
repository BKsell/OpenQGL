package main

import "testing"

func TestE70U8LClassifyBlock(t *testing.T) {
	for _, v := range E70U8LBlock { if E70U8LClassify(v) != E70U8LClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70U8LClassifyWarn(t *testing.T) {
	for _, v := range E70U8LWarn { if E70U8LClassify(v) != E70U8LClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70U8LClassifyAllow(t *testing.T) {
	for _, v := range E70U8LAllow { if E70U8LClassify(v) != E70U8LClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70U8LClassifyUnknown(t *testing.T) {
	if E70U8LClassify("zzz-not-in-any-e70-catalog-99") != E70U8LClassUnknown { t.Fatal("unknown") }
}

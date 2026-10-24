package main

import "testing"

func TestE70JCHClassifyBlock(t *testing.T) {
	for _, v := range E70JCHBlock { if E70JCHClassify(v) != E70JCHClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70JCHClassifyWarn(t *testing.T) {
	for _, v := range E70JCHWarn { if E70JCHClassify(v) != E70JCHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70JCHClassifyAllow(t *testing.T) {
	for _, v := range E70JCHAllow { if E70JCHClassify(v) != E70JCHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70JCHClassifyUnknown(t *testing.T) {
	if E70JCHClassify("zzz-not-in-any-e70-catalog-99") != E70JCHClassUnknown { t.Fatal("unknown") }
}

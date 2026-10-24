package main

import "testing"

func TestE70PSVClassifyBlock(t *testing.T) {
	for _, v := range E70PSVBlock { if E70PSVClassify(v) != E70PSVClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PSVClassifyWarn(t *testing.T) {
	for _, v := range E70PSVWarn { if E70PSVClassify(v) != E70PSVClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PSVClassifyAllow(t *testing.T) {
	for _, v := range E70PSVAllow { if E70PSVClassify(v) != E70PSVClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PSVClassifyUnknown(t *testing.T) {
	if E70PSVClassify("zzz-not-in-any-e70-catalog-99") != E70PSVClassUnknown { t.Fatal("unknown") }
}

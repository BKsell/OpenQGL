package main

import "testing"

func TestE70BAOClassifyBlock(t *testing.T) {
	for _, v := range E70BAOBlock { if E70BAOClassify(v) != E70BAOClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70BAOClassifyWarn(t *testing.T) {
	for _, v := range E70BAOWarn { if E70BAOClassify(v) != E70BAOClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70BAOClassifyAllow(t *testing.T) {
	for _, v := range E70BAOAllow { if E70BAOClassify(v) != E70BAOClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70BAOClassifyUnknown(t *testing.T) {
	if E70BAOClassify("zzz-not-in-any-e70-catalog-99") != E70BAOClassUnknown { t.Fatal("unknown") }
}

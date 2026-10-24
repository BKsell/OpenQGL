package main

import "testing"

func TestE70PPKClassifyBlock(t *testing.T) {
	for _, v := range E70PPKBlock { if E70PPKClassify(v) != E70PPKClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PPKClassifyWarn(t *testing.T) {
	for _, v := range E70PPKWarn { if E70PPKClassify(v) != E70PPKClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PPKClassifyAllow(t *testing.T) {
	for _, v := range E70PPKAllow { if E70PPKClassify(v) != E70PPKClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PPKClassifyUnknown(t *testing.T) {
	if E70PPKClassify("zzz-not-in-any-e70-catalog-99") != E70PPKClassUnknown { t.Fatal("unknown") }
}

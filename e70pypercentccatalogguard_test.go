package main

import "testing"

func TestE70PPCClassifyBlock(t *testing.T) {
	for _, v := range E70PPCBlock { if E70PPCClassify(v) != E70PPCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PPCClassifyWarn(t *testing.T) {
	for _, v := range E70PPCWarn { if E70PPCClassify(v) != E70PPCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PPCClassifyAllow(t *testing.T) {
	for _, v := range E70PPCAllow { if E70PPCClassify(v) != E70PPCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PPCClassifyUnknown(t *testing.T) {
	if E70PPCClassify("zzz-not-in-any-e70-catalog-99") != E70PPCClassUnknown { t.Fatal("unknown") }
}

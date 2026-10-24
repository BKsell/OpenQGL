package main

import "testing"

func TestE70PHCClassifyBlock(t *testing.T) {
	for _, v := range E70PHCBlock { if E70PHCClassify(v) != E70PHCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PHCClassifyWarn(t *testing.T) {
	for _, v := range E70PHCWarn { if E70PHCClassify(v) != E70PHCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PHCClassifyAllow(t *testing.T) {
	for _, v := range E70PHCAllow { if E70PHCClassify(v) != E70PHCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PHCClassifyUnknown(t *testing.T) {
	if E70PHCClassify("zzz-not-in-any-e70-catalog-99") != E70PHCClassUnknown { t.Fatal("unknown") }
}

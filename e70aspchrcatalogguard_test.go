package main

import "testing"

func TestE70APCClassifyBlock(t *testing.T) {
	for _, v := range E70APCBlock { if E70APCClassify(v) != E70APCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70APCClassifyWarn(t *testing.T) {
	for _, v := range E70APCWarn { if E70APCClassify(v) != E70APCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70APCClassifyAllow(t *testing.T) {
	for _, v := range E70APCAllow { if E70APCClassify(v) != E70APCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70APCClassifyUnknown(t *testing.T) {
	if E70APCClassify("zzz-not-in-any-e70-catalog-99") != E70APCClassUnknown { t.Fatal("unknown") }
}

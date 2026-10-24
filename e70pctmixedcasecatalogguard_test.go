package main

import "testing"

func TestE70PMCClassifyBlock(t *testing.T) {
	for _, v := range E70PMCBlock { if E70PMCClassify(v) != E70PMCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PMCClassifyWarn(t *testing.T) {
	for _, v := range E70PMCWarn { if E70PMCClassify(v) != E70PMCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PMCClassifyAllow(t *testing.T) {
	for _, v := range E70PMCAllow { if E70PMCClassify(v) != E70PMCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PMCClassifyUnknown(t *testing.T) {
	if E70PMCClassify("zzz-not-in-any-e70-catalog-99") != E70PMCClassUnknown { t.Fatal("unknown") }
}

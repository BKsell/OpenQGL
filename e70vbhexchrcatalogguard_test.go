package main

import "testing"

func TestE70VHCClassifyBlock(t *testing.T) {
	for _, v := range E70VHCBlock { if E70VHCClassify(v) != E70VHCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70VHCClassifyWarn(t *testing.T) {
	for _, v := range E70VHCWarn { if E70VHCClassify(v) != E70VHCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70VHCClassifyAllow(t *testing.T) {
	for _, v := range E70VHCAllow { if E70VHCClassify(v) != E70VHCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70VHCClassifyUnknown(t *testing.T) {
	if E70VHCClassify("zzz-not-in-any-e70-catalog-99") != E70VHCClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70VCWClassifyBlock(t *testing.T) {
	for _, v := range E70VCWBlock { if E70VCWClassify(v) != E70VCWClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70VCWClassifyWarn(t *testing.T) {
	for _, v := range E70VCWWarn { if E70VCWClassify(v) != E70VCWClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70VCWClassifyAllow(t *testing.T) {
	for _, v := range E70VCWAllow { if E70VCWClassify(v) != E70VCWClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70VCWClassifyUnknown(t *testing.T) {
	if E70VCWClassify("zzz-not-in-any-e70-catalog-99") != E70VCWClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE69VBCClassifyBlock(t *testing.T) {
	for _, v := range E69VBCBlock { if E69VBCClassify(v) != E69VBCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69VBCClassifyWarn(t *testing.T) {
	for _, v := range E69VBCWarn { if E69VBCClassify(v) != E69VBCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69VBCClassifyAllow(t *testing.T) {
	for _, v := range E69VBCAllow { if E69VBCClassify(v) != E69VBCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69VBCClassifyUnknown(t *testing.T) {
	if E69VBCClassify("zzz-not-in-any-e69-catalog-88") != E69VBCClassUnknown { t.Fatal("unknown") }
}

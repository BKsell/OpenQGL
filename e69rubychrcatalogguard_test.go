package main

import "testing"

func TestE69RBCClassifyBlock(t *testing.T) {
	for _, v := range E69RBCBlock { if E69RBCClassify(v) != E69RBCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69RBCClassifyWarn(t *testing.T) {
	for _, v := range E69RBCWarn { if E69RBCClassify(v) != E69RBCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69RBCClassifyAllow(t *testing.T) {
	for _, v := range E69RBCAllow { if E69RBCClassify(v) != E69RBCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69RBCClassifyUnknown(t *testing.T) {
	if E69RBCClassify("zzz-not-in-any-e69-catalog-88") != E69RBCClassUnknown { t.Fatal("unknown") }
}

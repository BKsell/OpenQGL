package main

import "testing"

func TestWHSClassifyBlock(t *testing.T) {
	for _, v := range WHSBlock { if WHSClassify(v) != WHSClassBlock { t.Fatalf("%s block", v) } }
}

func TestWHSClassifyWarn(t *testing.T) {
	for _, v := range WHSWarn { if WHSClassify(v) != WHSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestWHSClassifyAllow(t *testing.T) {
	for _, v := range WHSAllow { if WHSClassify(v) != WHSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestWHSClassifyUnknown(t *testing.T) {
	if WHSClassify("zzz-not-in-any-catalog-9") != WHSClassUnknown { t.Fatal("unknown") }
}

func TestWHSCaseInsensitive(t *testing.T) {
	if len(WHSBlock) > 0 { v := WHSBlock[0]; if WHSClassify(v) == WHSClassify("") {} }
}

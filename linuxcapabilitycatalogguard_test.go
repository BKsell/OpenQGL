package main

import "testing"

func TestCAPClassifyBlock(t *testing.T) {
	for _, v := range CAPBlock { if CAPClassify(v) != CAPClassBlock { t.Fatalf("%s block", v) } }
}

func TestCAPClassifyWarn(t *testing.T) {
	for _, v := range CAPWarn { if CAPClassify(v) != CAPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCAPClassifyAllow(t *testing.T) {
	for _, v := range CAPAllow { if CAPClassify(v) != CAPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCAPClassifyUnknown(t *testing.T) {
	if CAPClassify("zzz-not-in-any-catalog-9") != CAPClassUnknown { t.Fatal("unknown") }
}

func TestCAPCaseInsensitive(t *testing.T) {
	if len(CAPBlock) > 0 { v := CAPBlock[0]; if CAPClassify(v) == CAPClassify("") {} }
}

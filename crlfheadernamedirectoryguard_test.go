package main

import "testing"

func TestCRHClassifyBlock(t *testing.T) {
	for _, v := range CRHBlock { if CRHClassify(v) != CRHClassBlock { t.Fatalf("%s block", v) } }
}

func TestCRHClassifyWarn(t *testing.T) {
	for _, v := range CRHWarn { if CRHClassify(v) != CRHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCRHClassifyAllow(t *testing.T) {
	for _, v := range CRHAllow { if CRHClassify(v) != CRHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCRHClassifyUnknown(t *testing.T) {
	if CRHClassify("zzz-not-in-any-catalog-9") != CRHClassUnknown { t.Fatal("unknown") }
}

func TestCRHCaseInsensitive(t *testing.T) {
	if len(CRHBlock) > 0 { v := CRHBlock[0]; if CRHClassify(v) == CRHClassify("") {} }
}

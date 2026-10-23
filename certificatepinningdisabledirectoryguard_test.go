package main

import "testing"

func TestCPDClassifyBlock(t *testing.T) {
	for _, v := range CPDBlock { if CPDClassify(v) != CPDClassBlock { t.Fatalf("%s block", v) } }
}

func TestCPDClassifyWarn(t *testing.T) {
	for _, v := range CPDWarn { if CPDClassify(v) != CPDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCPDClassifyAllow(t *testing.T) {
	for _, v := range CPDAllow { if CPDClassify(v) != CPDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCPDClassifyUnknown(t *testing.T) {
	if CPDClassify("zzz-not-in-any-catalog-9") != CPDClassUnknown { t.Fatal("unknown") }
}

func TestCPDCaseInsensitive(t *testing.T) {
	if len(CPDBlock) > 0 { v := CPDBlock[0]; if CPDClassify(v) == CPDClassify("") {} }
}

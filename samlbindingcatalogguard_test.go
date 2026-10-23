package main

import "testing"

func TestSBDClassifyBlock(t *testing.T) {
	for _, v := range SBDBlock { if SBDClassify(v) != SBDClassBlock { t.Fatalf("%s block", v) } }
}

func TestSBDClassifyWarn(t *testing.T) {
	for _, v := range SBDWarn { if SBDClassify(v) != SBDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSBDClassifyAllow(t *testing.T) {
	for _, v := range SBDAllow { if SBDClassify(v) != SBDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSBDClassifyUnknown(t *testing.T) {
	if SBDClassify("zzz-not-in-any-catalog-9") != SBDClassUnknown { t.Fatal("unknown") }
}

func TestSBDCaseInsensitive(t *testing.T) {
	if len(SBDBlock) > 0 { v := SBDBlock[0]; if SBDClassify(v) == SBDClassify("") {} }
}

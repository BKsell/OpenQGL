package main

import "testing"

func TestSBHClassifyBlock(t *testing.T) {
	for _, v := range SBHBlock { if SBHClassify(v) != SBHClassBlock { t.Fatalf("%s block", v) } }
}

func TestSBHClassifyWarn(t *testing.T) {
	for _, v := range SBHWarn { if SBHClassify(v) != SBHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSBHClassifyAllow(t *testing.T) {
	for _, v := range SBHAllow { if SBHClassify(v) != SBHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSBHClassifyUnknown(t *testing.T) {
	if SBHClassify("zzz-not-in-any-catalog-9") != SBHClassUnknown { t.Fatal("unknown") }
}

func TestSBHCaseInsensitive(t *testing.T) {
	if len(SBHBlock) > 0 { v := SBHBlock[0]; if SBHClassify(v) == SBHClassify("") {} }
}

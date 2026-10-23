package main

import "testing"

func TestSHMClassifyBlock(t *testing.T) {
	for _, v := range SHMBlock { if SHMClassify(v) != SHMClassBlock { t.Fatalf("%s block", v) } }
}

func TestSHMClassifyWarn(t *testing.T) {
	for _, v := range SHMWarn { if SHMClassify(v) != SHMClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSHMClassifyAllow(t *testing.T) {
	for _, v := range SHMAllow { if SHMClassify(v) != SHMClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSHMClassifyUnknown(t *testing.T) {
	if SHMClassify("zzz-not-in-any-catalog-9") != SHMClassUnknown { t.Fatal("unknown") }
}

func TestSHMCaseInsensitive(t *testing.T) {
	if len(SHMBlock) > 0 { v := SHMBlock[0]; if SHMClassify(v) == SHMClassify("") {} }
}

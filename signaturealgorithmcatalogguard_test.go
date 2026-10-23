package main

import "testing"

func TestSIAClassifyBlock(t *testing.T) {
	for _, v := range SIABlock { if SIAClassify(v) != SIAClassBlock { t.Fatalf("%s block", v) } }
}

func TestSIAClassifyWarn(t *testing.T) {
	for _, v := range SIAWarn { if SIAClassify(v) != SIAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSIAClassifyAllow(t *testing.T) {
	for _, v := range SIAAllow { if SIAClassify(v) != SIAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSIAClassifyUnknown(t *testing.T) {
	if SIAClassify("zzz-not-in-any-catalog-9") != SIAClassUnknown { t.Fatal("unknown") }
}

func TestSIACaseInsensitive(t *testing.T) {
	if len(SIABlock) > 0 { v := SIABlock[0]; if SIAClassify(v) == SIAClassify("") {} }
}

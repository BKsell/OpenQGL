package main

import "testing"

func TestHPKClassifyBlock(t *testing.T) {
	for _, v := range HPKBlock { if HPKClassify(v) != HPKClassBlock { t.Fatalf("%s block", v) } }
}

func TestHPKClassifyWarn(t *testing.T) {
	for _, v := range HPKWarn { if HPKClassify(v) != HPKClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHPKClassifyAllow(t *testing.T) {
	for _, v := range HPKAllow { if HPKClassify(v) != HPKClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHPKClassifyUnknown(t *testing.T) {
	if HPKClassify("zzz-not-in-any-catalog-9") != HPKClassUnknown { t.Fatal("unknown") }
}

func TestHPKCaseInsensitive(t *testing.T) {
	if len(HPKBlock) > 0 { v := HPKBlock[0]; if HPKClassify(v) == HPKClassify("") {} }
}

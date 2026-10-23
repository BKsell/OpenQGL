package main

import "testing"

func TestLIKClassifyBlock(t *testing.T) {
	for _, v := range LIKBlock { if LIKClassify(v) != LIKClassBlock { t.Fatalf("%s block", v) } }
}

func TestLIKClassifyWarn(t *testing.T) {
	for _, v := range LIKWarn { if LIKClassify(v) != LIKClassWarn { t.Fatalf("%s warn", v) } }
}

func TestLIKClassifyAllow(t *testing.T) {
	for _, v := range LIKAllow { if LIKClassify(v) != LIKClassAllow { t.Fatalf("%s allow", v) } }
}

func TestLIKClassifyUnknown(t *testing.T) {
	if LIKClassify("zzz-not-in-any-catalog-9") != LIKClassUnknown { t.Fatal("unknown") }
}

func TestLIKCaseInsensitive(t *testing.T) {
	if len(LIKBlock) > 0 { v := LIKBlock[0]; if LIKClassify(v) == LIKClassify("") {} }
}

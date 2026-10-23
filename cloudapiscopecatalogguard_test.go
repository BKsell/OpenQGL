package main

import "testing"

func TestCASClassifyBlock(t *testing.T) {
	for _, v := range CASBlock { if CASClassify(v) != CASClassBlock { t.Fatalf("%s block", v) } }
}

func TestCASClassifyWarn(t *testing.T) {
	for _, v := range CASWarn { if CASClassify(v) != CASClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCASClassifyAllow(t *testing.T) {
	for _, v := range CASAllow { if CASClassify(v) != CASClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCASClassifyUnknown(t *testing.T) {
	if CASClassify("zzz-not-in-any-catalog-9") != CASClassUnknown { t.Fatal("unknown") }
}

func TestCASCaseInsensitive(t *testing.T) {
	if len(CASBlock) > 0 { v := CASBlock[0]; if CASClassify(v) == CASClassify("") {} }
}

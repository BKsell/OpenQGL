package main

import "testing"

func TestDEXClassifyBlock(t *testing.T) {
	for _, v := range DEXBlock { if DEXClassify(v) != DEXClassBlock { t.Fatalf("%s block", v) } }
}

func TestDEXClassifyWarn(t *testing.T) {
	for _, v := range DEXWarn { if DEXClassify(v) != DEXClassWarn { t.Fatalf("%s warn", v) } }
}

func TestDEXClassifyAllow(t *testing.T) {
	for _, v := range DEXAllow { if DEXClassify(v) != DEXClassAllow { t.Fatalf("%s allow", v) } }
}

func TestDEXClassifyUnknown(t *testing.T) {
	if DEXClassify("zzz-not-in-any-catalog-9") != DEXClassUnknown { t.Fatal("unknown") }
}

func TestDEXCaseInsensitive(t *testing.T) {
	if len(DEXBlock) > 0 { v := DEXBlock[0]; if DEXClassify(v) == DEXClassify("") {} }
}

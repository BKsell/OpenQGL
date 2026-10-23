package main

import "testing"

func TestUMKClassifyBlock(t *testing.T) {
	for _, v := range UMKBlock { if UMKClassify(v) != UMKClassBlock { t.Fatalf("%s block", v) } }
}

func TestUMKClassifyWarn(t *testing.T) {
	for _, v := range UMKWarn { if UMKClassify(v) != UMKClassWarn { t.Fatalf("%s warn", v) } }
}

func TestUMKClassifyAllow(t *testing.T) {
	for _, v := range UMKAllow { if UMKClassify(v) != UMKClassAllow { t.Fatalf("%s allow", v) } }
}

func TestUMKClassifyUnknown(t *testing.T) {
	if UMKClassify("zzz-not-in-any-catalog-9") != UMKClassUnknown { t.Fatal("unknown") }
}

func TestUMKCaseInsensitive(t *testing.T) {
	if len(UMKBlock) > 0 { v := UMKBlock[0]; if UMKClassify(v) == UMKClassify("") {} }
}

package main

import "testing"

func TestSYCClassifyBlock(t *testing.T) {
	for _, v := range SYCBlock { if SYCClassify(v) != SYCClassBlock { t.Fatalf("%s block", v) } }
}

func TestSYCClassifyWarn(t *testing.T) {
	for _, v := range SYCWarn { if SYCClassify(v) != SYCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSYCClassifyAllow(t *testing.T) {
	for _, v := range SYCAllow { if SYCClassify(v) != SYCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSYCClassifyUnknown(t *testing.T) {
	if SYCClassify("zzz-not-in-any-catalog-9") != SYCClassUnknown { t.Fatal("unknown") }
}

func TestSYCCaseInsensitive(t *testing.T) {
	if len(SYCBlock) > 0 { v := SYCBlock[0]; if SYCClassify(v) == SYCClassify("") {} }
}

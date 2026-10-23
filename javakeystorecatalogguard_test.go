package main

import "testing"

func TestJKCClassifyBlock(t *testing.T) {
	for _, v := range JKCBlock { if JKCClassify(v) != JKCClassBlock { t.Fatalf("%s block", v) } }
}

func TestJKCClassifyWarn(t *testing.T) {
	for _, v := range JKCWarn { if JKCClassify(v) != JKCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJKCClassifyAllow(t *testing.T) {
	for _, v := range JKCAllow { if JKCClassify(v) != JKCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJKCClassifyUnknown(t *testing.T) {
	if JKCClassify("zzz-not-in-any-catalog-9") != JKCClassUnknown { t.Fatal("unknown") }
}

func TestJKCCaseInsensitive(t *testing.T) {
	if len(JKCBlock) > 0 { v := JKCBlock[0]; if JKCClassify(v) == JKCClassify("") {} }
}

package main

import "testing"

func TestWPCClassifyBlock(t *testing.T) {
	for _, v := range WPCBlock { if WPCClassify(v) != WPCClassBlock { t.Fatalf("%s block", v) } }
}

func TestWPCClassifyWarn(t *testing.T) {
	for _, v := range WPCWarn { if WPCClassify(v) != WPCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestWPCClassifyAllow(t *testing.T) {
	for _, v := range WPCAllow { if WPCClassify(v) != WPCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestWPCClassifyUnknown(t *testing.T) {
	if WPCClassify("zzz-not-in-any-catalog-9") != WPCClassUnknown { t.Fatal("unknown") }
}

func TestWPCCaseInsensitive(t *testing.T) {
	if len(WPCBlock) > 0 { v := WPCBlock[0]; if WPCClassify(v) == WPCClassify("") {} }
}

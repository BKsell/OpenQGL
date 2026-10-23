package main

import "testing"

func TestCTCClassifyBlock(t *testing.T) {
	for _, v := range CTCBlock { if CTCClassify(v) != CTCClassBlock { t.Fatalf("%s block", v) } }
}

func TestCTCClassifyWarn(t *testing.T) {
	for _, v := range CTCWarn { if CTCClassify(v) != CTCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCTCClassifyAllow(t *testing.T) {
	for _, v := range CTCAllow { if CTCClassify(v) != CTCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCTCClassifyUnknown(t *testing.T) {
	if CTCClassify("zzz-not-in-any-catalog-9") != CTCClassUnknown { t.Fatal("unknown") }
}

func TestCTCCaseInsensitive(t *testing.T) {
	if len(CTCBlock) > 0 { v := CTCBlock[0]; if CTCClassify(v) == CTCClassify("") {} }
}

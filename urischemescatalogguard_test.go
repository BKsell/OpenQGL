package main

import "testing"

func TestUSCClassifyBlock(t *testing.T) {
	for _, v := range USCBlock { if USCClassify(v) != USCClassBlock { t.Fatalf("%s block", v) } }
}

func TestUSCClassifyWarn(t *testing.T) {
	for _, v := range USCWarn { if USCClassify(v) != USCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestUSCClassifyAllow(t *testing.T) {
	for _, v := range USCAllow { if USCClassify(v) != USCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestUSCClassifyUnknown(t *testing.T) {
	if USCClassify("zzz-not-in-any-catalog-9") != USCClassUnknown { t.Fatal("unknown") }
}

func TestUSCCaseInsensitive(t *testing.T) {
	if len(USCBlock) > 0 { v := USCBlock[0]; if USCClassify(v) == USCClassify("") {} }
}

package main

import "testing"

func TestCECClassifyBlock(t *testing.T) {
	for _, v := range CECBlock { if CECClassify(v) != CECClassBlock { t.Fatalf("%s block", v) } }
}

func TestCECClassifyWarn(t *testing.T) {
	for _, v := range CECWarn { if CECClassify(v) != CECClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCECClassifyAllow(t *testing.T) {
	for _, v := range CECAllow { if CECClassify(v) != CECClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCECClassifyUnknown(t *testing.T) {
	if CECClassify("zzz-not-in-any-catalog-9") != CECClassUnknown { t.Fatal("unknown") }
}

func TestCECCaseInsensitive(t *testing.T) {
	if len(CECBlock) > 0 { v := CECBlock[0]; if CECClassify(v) == CECClassify("") {} }
}

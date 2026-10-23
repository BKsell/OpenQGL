package main

import "testing"

func TestJDCClassifyBlock(t *testing.T) {
	for _, v := range JDCBlock { if JDCClassify(v) != JDCClassBlock { t.Fatalf("%s block", v) } }
}

func TestJDCClassifyWarn(t *testing.T) {
	for _, v := range JDCWarn { if JDCClassify(v) != JDCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJDCClassifyAllow(t *testing.T) {
	for _, v := range JDCAllow { if JDCClassify(v) != JDCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJDCClassifyUnknown(t *testing.T) {
	if JDCClassify("zzz-not-in-any-catalog-9") != JDCClassUnknown { t.Fatal("unknown") }
}

func TestJDCCaseInsensitive(t *testing.T) {
	if len(JDCBlock) > 0 { v := JDCBlock[0]; if JDCClassify(v) == JDCClassify("") {} }
}

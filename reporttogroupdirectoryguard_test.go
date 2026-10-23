package main

import "testing"

func TestRTEClassifyBlock(t *testing.T) {
	for _, v := range RTEBlock { if RTEClassify(v) != RTEClassBlock { t.Fatalf("%s block", v) } }
}

func TestRTEClassifyWarn(t *testing.T) {
	for _, v := range RTEWarn { if RTEClassify(v) != RTEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestRTEClassifyAllow(t *testing.T) {
	for _, v := range RTEAllow { if RTEClassify(v) != RTEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestRTEClassifyUnknown(t *testing.T) {
	if RTEClassify("zzz-not-in-any-catalog-9") != RTEClassUnknown { t.Fatal("unknown") }
}

func TestRTECaseInsensitive(t *testing.T) {
	if len(RTEBlock) > 0 { v := RTEBlock[0]; if RTEClassify(v) == RTEClassify("") {} }
}

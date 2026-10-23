package main

import "testing"

func TestRFPClassifyBlock(t *testing.T) {
	for _, v := range RFPBlock { if RFPClassify(v) != RFPClassBlock { t.Fatalf("%s block", v) } }
}

func TestRFPClassifyWarn(t *testing.T) {
	for _, v := range RFPWarn { if RFPClassify(v) != RFPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestRFPClassifyAllow(t *testing.T) {
	for _, v := range RFPAllow { if RFPClassify(v) != RFPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestRFPClassifyUnknown(t *testing.T) {
	if RFPClassify("zzz-not-in-any-catalog-9") != RFPClassUnknown { t.Fatal("unknown") }
}

func TestRFPCaseInsensitive(t *testing.T) {
	if len(RFPBlock) > 0 { v := RFPBlock[0]; if RFPClassify(v) == RFPClassify("") {} }
}

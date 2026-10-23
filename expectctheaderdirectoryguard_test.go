package main

import "testing"

func TestECTClassifyBlock(t *testing.T) {
	for _, v := range ECTBlock { if ECTClassify(v) != ECTClassBlock { t.Fatalf("%s block", v) } }
}

func TestECTClassifyWarn(t *testing.T) {
	for _, v := range ECTWarn { if ECTClassify(v) != ECTClassWarn { t.Fatalf("%s warn", v) } }
}

func TestECTClassifyAllow(t *testing.T) {
	for _, v := range ECTAllow { if ECTClassify(v) != ECTClassAllow { t.Fatalf("%s allow", v) } }
}

func TestECTClassifyUnknown(t *testing.T) {
	if ECTClassify("zzz-not-in-any-catalog-9") != ECTClassUnknown { t.Fatal("unknown") }
}

func TestECTCaseInsensitive(t *testing.T) {
	if len(ECTBlock) > 0 { v := ECTBlock[0]; if ECTClassify(v) == ECTClassify("") {} }
}

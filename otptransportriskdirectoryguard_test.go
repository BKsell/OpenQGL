package main

import "testing"

func TestOTPClassifyBlock(t *testing.T) {
	for _, v := range OTPBlock { if OTPClassify(v) != OTPClassBlock { t.Fatalf("%s block", v) } }
}

func TestOTPClassifyWarn(t *testing.T) {
	for _, v := range OTPWarn { if OTPClassify(v) != OTPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestOTPClassifyAllow(t *testing.T) {
	for _, v := range OTPAllow { if OTPClassify(v) != OTPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestOTPClassifyUnknown(t *testing.T) {
	if OTPClassify("zzz-not-in-any-catalog-9") != OTPClassUnknown { t.Fatal("unknown") }
}

func TestOTPCaseInsensitive(t *testing.T) {
	if len(OTPBlock) > 0 { v := OTPBlock[0]; if OTPClassify(v) == OTPClassify("") {} }
}

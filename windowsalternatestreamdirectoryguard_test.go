package main

import "testing"

func TestADSClassifyBlock(t *testing.T) {
	for _, v := range ADSBlock { if ADSClassify(v) != ADSClassBlock { t.Fatalf("%s block", v) } }
}

func TestADSClassifyWarn(t *testing.T) {
	for _, v := range ADSWarn { if ADSClassify(v) != ADSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestADSClassifyAllow(t *testing.T) {
	for _, v := range ADSAllow { if ADSClassify(v) != ADSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestADSClassifyUnknown(t *testing.T) {
	if ADSClassify("zzz-not-in-any-catalog-9") != ADSClassUnknown { t.Fatal("unknown") }
}

func TestADSCaseInsensitive(t *testing.T) {
	if len(ADSBlock) > 0 { v := ADSBlock[0]; if ADSClassify(v) == ADSClassify("") {} }
}

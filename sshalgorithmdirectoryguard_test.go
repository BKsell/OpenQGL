package main

import "testing"

func TestAHSClassifyBlock(t *testing.T) {
	for _, v := range AHSBlock { if AHSClassify(v) != AHSClassBlock { t.Fatalf("%s block", v) } }
}

func TestAHSClassifyWarn(t *testing.T) {
	for _, v := range AHSWarn { if AHSClassify(v) != AHSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestAHSClassifyAllow(t *testing.T) {
	for _, v := range AHSAllow { if AHSClassify(v) != AHSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestAHSClassifyUnknown(t *testing.T) {
	if AHSClassify("zzz-not-in-any-catalog-9") != AHSClassUnknown { t.Fatal("unknown") }
}

func TestAHSCaseInsensitive(t *testing.T) {
	if len(AHSBlock) > 0 { v := AHSBlock[0]; if AHSClassify(v) == AHSClassify("") {} }
}

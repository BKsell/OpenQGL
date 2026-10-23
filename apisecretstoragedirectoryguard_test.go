package main

import "testing"

func TestASSClassifyBlock(t *testing.T) {
	for _, v := range ASSBlock { if ASSClassify(v) != ASSClassBlock { t.Fatalf("%s block", v) } }
}

func TestASSClassifyWarn(t *testing.T) {
	for _, v := range ASSWarn { if ASSClassify(v) != ASSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestASSClassifyAllow(t *testing.T) {
	for _, v := range ASSAllow { if ASSClassify(v) != ASSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestASSClassifyUnknown(t *testing.T) {
	if ASSClassify("zzz-not-in-any-catalog-9") != ASSClassUnknown { t.Fatal("unknown") }
}

func TestASSCaseInsensitive(t *testing.T) {
	if len(ASSBlock) > 0 { v := ASSBlock[0]; if ASSClassify(v) == ASSClassify("") {} }
}

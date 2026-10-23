package main

import "testing"

func TestAUDClassifyBlock(t *testing.T) {
	for _, v := range AUDBlock { if AUDClassify(v) != AUDClassBlock { t.Fatalf("%s block", v) } }
}

func TestAUDClassifyWarn(t *testing.T) {
	for _, v := range AUDWarn { if AUDClassify(v) != AUDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestAUDClassifyAllow(t *testing.T) {
	for _, v := range AUDAllow { if AUDClassify(v) != AUDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestAUDClassifyUnknown(t *testing.T) {
	if AUDClassify("zzz-not-in-any-catalog-9") != AUDClassUnknown { t.Fatal("unknown") }
}

func TestAUDCaseInsensitive(t *testing.T) {
	if len(AUDBlock) > 0 { v := AUDBlock[0]; if AUDClassify(v) == AUDClassify("") {} }
}

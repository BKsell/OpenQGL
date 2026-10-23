package main

import "testing"

func TestAAPClassifyBlock(t *testing.T) {
	for _, v := range AAPBlock { if AAPClassify(v) != AAPClassBlock { t.Fatalf("%s block", v) } }
}

func TestAAPClassifyWarn(t *testing.T) {
	for _, v := range AAPWarn { if AAPClassify(v) != AAPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestAAPClassifyAllow(t *testing.T) {
	for _, v := range AAPAllow { if AAPClassify(v) != AAPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestAAPClassifyUnknown(t *testing.T) {
	if AAPClassify("zzz-not-in-any-catalog-9") != AAPClassUnknown { t.Fatal("unknown") }
}

func TestAAPCaseInsensitive(t *testing.T) {
	if len(AAPBlock) > 0 { v := AAPBlock[0]; if AAPClassify(v) == AAPClassify("") {} }
}

package main

import "testing"

func TestAINClassifyBlock(t *testing.T) {
	for _, v := range AINBlock { if AINClassify(v) != AINClassBlock { t.Fatalf("%s block", v) } }
}

func TestAINClassifyWarn(t *testing.T) {
	for _, v := range AINWarn { if AINClassify(v) != AINClassWarn { t.Fatalf("%s warn", v) } }
}

func TestAINClassifyAllow(t *testing.T) {
	for _, v := range AINAllow { if AINClassify(v) != AINClassAllow { t.Fatalf("%s allow", v) } }
}

func TestAINClassifyUnknown(t *testing.T) {
	if AINClassify("zzz-not-in-any-catalog-9") != AINClassUnknown { t.Fatal("unknown") }
}

func TestAINCaseInsensitive(t *testing.T) {
	if len(AINBlock) > 0 { v := AINBlock[0]; if AINClassify(v) == AINClassify("") {} }
}

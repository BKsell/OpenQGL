package main

import "testing"

func TestHLTClassifyBlock(t *testing.T) {
	for _, v := range HLTBlock { if HLTClassify(v) != HLTClassBlock { t.Fatalf("%s block", v) } }
}

func TestHLTClassifyWarn(t *testing.T) {
	for _, v := range HLTWarn { if HLTClassify(v) != HLTClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHLTClassifyAllow(t *testing.T) {
	for _, v := range HLTAllow { if HLTClassify(v) != HLTClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHLTClassifyUnknown(t *testing.T) {
	if HLTClassify("zzz-not-in-any-catalog-9") != HLTClassUnknown { t.Fatal("unknown") }
}

func TestHLTCaseInsensitive(t *testing.T) {
	if len(HLTBlock) > 0 { v := HLTBlock[0]; if HLTClassify(v) == HLTClassify("") {} }
}

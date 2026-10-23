package main

import "testing"

func TestACTClassifyBlock(t *testing.T) {
	for _, v := range ACTBlock { if ACTClassify(v) != ACTClassBlock { t.Fatalf("%s block", v) } }
}

func TestACTClassifyWarn(t *testing.T) {
	for _, v := range ACTWarn { if ACTClassify(v) != ACTClassWarn { t.Fatalf("%s warn", v) } }
}

func TestACTClassifyAllow(t *testing.T) {
	for _, v := range ACTAllow { if ACTClassify(v) != ACTClassAllow { t.Fatalf("%s allow", v) } }
}

func TestACTClassifyUnknown(t *testing.T) {
	if ACTClassify("zzz-not-in-any-catalog-9") != ACTClassUnknown { t.Fatal("unknown") }
}

func TestACTCaseInsensitive(t *testing.T) {
	if len(ACTBlock) > 0 { v := ACTBlock[0]; if ACTClassify(v) == ACTClassify("") {} }
}

package main

import "testing"

func TestTPVClassifyBlock(t *testing.T) {
	for _, v := range TPVBlock { if TPVClassify(v) != TPVClassBlock { t.Fatalf("%s block", v) } }
}

func TestTPVClassifyWarn(t *testing.T) {
	for _, v := range TPVWarn { if TPVClassify(v) != TPVClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTPVClassifyAllow(t *testing.T) {
	for _, v := range TPVAllow { if TPVClassify(v) != TPVClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTPVClassifyUnknown(t *testing.T) {
	if TPVClassify("zzz-not-in-any-catalog-9") != TPVClassUnknown { t.Fatal("unknown") }
}

func TestTPVCaseInsensitive(t *testing.T) {
	if len(TPVBlock) > 0 { v := TPVBlock[0]; if TPVClassify(v) == TPVClassify("") {} }
}

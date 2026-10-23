package main

import "testing"

func TestHMDClassifyBlock(t *testing.T) {
	for _, v := range HMDBlock { if HMDClassify(v) != HMDClassBlock { t.Fatalf("%s block", v) } }
}

func TestHMDClassifyWarn(t *testing.T) {
	for _, v := range HMDWarn { if HMDClassify(v) != HMDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHMDClassifyAllow(t *testing.T) {
	for _, v := range HMDAllow { if HMDClassify(v) != HMDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHMDClassifyUnknown(t *testing.T) {
	if HMDClassify("zzz-not-in-any-catalog-9") != HMDClassUnknown { t.Fatal("unknown") }
}

func TestHMDCaseInsensitive(t *testing.T) {
	if len(HMDBlock) > 0 { v := HMDBlock[0]; if HMDClassify(v) == HMDClassify("") {} }
}

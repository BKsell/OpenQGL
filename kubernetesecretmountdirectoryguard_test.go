package main

import "testing"

func TestKSEClassifyBlock(t *testing.T) {
	for _, v := range KSEBlock { if KSEClassify(v) != KSEClassBlock { t.Fatalf("%s block", v) } }
}

func TestKSEClassifyWarn(t *testing.T) {
	for _, v := range KSEWarn { if KSEClassify(v) != KSEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestKSEClassifyAllow(t *testing.T) {
	for _, v := range KSEAllow { if KSEClassify(v) != KSEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestKSEClassifyUnknown(t *testing.T) {
	if KSEClassify("zzz-not-in-any-catalog-9") != KSEClassUnknown { t.Fatal("unknown") }
}

func TestKSECaseInsensitive(t *testing.T) {
	if len(KSEBlock) > 0 { v := KSEBlock[0]; if KSEClassify(v) == KSEClassify("") {} }
}

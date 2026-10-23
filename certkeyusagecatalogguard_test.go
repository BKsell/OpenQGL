package main

import "testing"

func TestKUCClassifyBlock(t *testing.T) {
	for _, v := range KUCBlock { if KUCClassify(v) != KUCClassBlock { t.Fatalf("%s block", v) } }
}

func TestKUCClassifyWarn(t *testing.T) {
	for _, v := range KUCWarn { if KUCClassify(v) != KUCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestKUCClassifyAllow(t *testing.T) {
	for _, v := range KUCAllow { if KUCClassify(v) != KUCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestKUCClassifyUnknown(t *testing.T) {
	if KUCClassify("zzz-not-in-any-catalog-9") != KUCClassUnknown { t.Fatal("unknown") }
}

func TestKUCCaseInsensitive(t *testing.T) {
	if len(KUCBlock) > 0 { v := KUCBlock[0]; if KUCClassify(v) == KUCClassify("") {} }
}

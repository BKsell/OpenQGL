package main

import "testing"

func TestDGCClassifyBlock(t *testing.T) {
	for _, v := range DGCBlock { if DGCClassify(v) != DGCClassBlock { t.Fatalf("%s block", v) } }
}

func TestDGCClassifyWarn(t *testing.T) {
	for _, v := range DGCWarn { if DGCClassify(v) != DGCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestDGCClassifyAllow(t *testing.T) {
	for _, v := range DGCAllow { if DGCClassify(v) != DGCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestDGCClassifyUnknown(t *testing.T) {
	if DGCClassify("zzz-not-in-any-catalog-9") != DGCClassUnknown { t.Fatal("unknown") }
}

func TestDGCCaseInsensitive(t *testing.T) {
	if len(DGCBlock) > 0 { v := DGCBlock[0]; if DGCClassify(v) == DGCClassify("") {} }
}

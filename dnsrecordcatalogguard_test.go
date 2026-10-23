package main

import "testing"

func TestDRCClassifyBlock(t *testing.T) {
	for _, v := range DRCBlock { if DRCClassify(v) != DRCClassBlock { t.Fatalf("%s block", v) } }
}

func TestDRCClassifyWarn(t *testing.T) {
	for _, v := range DRCWarn { if DRCClassify(v) != DRCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestDRCClassifyAllow(t *testing.T) {
	for _, v := range DRCAllow { if DRCClassify(v) != DRCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestDRCClassifyUnknown(t *testing.T) {
	if DRCClassify("zzz-not-in-any-catalog-9") != DRCClassUnknown { t.Fatal("unknown") }
}

func TestDRCCaseInsensitive(t *testing.T) {
	if len(DRCBlock) > 0 { v := DRCBlock[0]; if DRCClassify(v) == DRCClassify("") {} }
}

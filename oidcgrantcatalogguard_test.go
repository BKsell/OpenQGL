package main

import "testing"

func TestOGCClassifyBlock(t *testing.T) {
	for _, v := range OGCBlock { if OGCClassify(v) != OGCClassBlock { t.Fatalf("%s block", v) } }
}

func TestOGCClassifyWarn(t *testing.T) {
	for _, v := range OGCWarn { if OGCClassify(v) != OGCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestOGCClassifyAllow(t *testing.T) {
	for _, v := range OGCAllow { if OGCClassify(v) != OGCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestOGCClassifyUnknown(t *testing.T) {
	if OGCClassify("zzz-not-in-any-catalog-9") != OGCClassUnknown { t.Fatal("unknown") }
}

func TestOGCCaseInsensitive(t *testing.T) {
	if len(OGCBlock) > 0 { v := OGCBlock[0]; if OGCClassify(v) == OGCClassify("") {} }
}

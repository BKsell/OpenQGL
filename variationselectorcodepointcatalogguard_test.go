package main

import "testing"

func TestVSCClassifyBlock(t *testing.T) {
	for _, v := range VSCBlock { if VSCClassify(v) != VSCClassBlock { t.Fatalf("%s block", v) } }
}

func TestVSCClassifyWarn(t *testing.T) {
	for _, v := range VSCWarn { if VSCClassify(v) != VSCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestVSCClassifyAllow(t *testing.T) {
	for _, v := range VSCAllow { if VSCClassify(v) != VSCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestVSCClassifyUnknown(t *testing.T) {
	if VSCClassify("zzz-not-in-any-catalog-11") != VSCClassUnknown { t.Fatal("unknown") }
}

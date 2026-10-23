package main

import "testing"

func TestCMCClassifyBlock(t *testing.T) {
	for _, v := range CMCBlock { if CMCClassify(v) != CMCClassBlock { t.Fatalf("%s block", v) } }
}

func TestCMCClassifyWarn(t *testing.T) {
	for _, v := range CMCWarn { if CMCClassify(v) != CMCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCMCClassifyAllow(t *testing.T) {
	for _, v := range CMCAllow { if CMCClassify(v) != CMCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCMCClassifyUnknown(t *testing.T) {
	if CMCClassify("zzz-not-in-any-catalog-11") != CMCClassUnknown { t.Fatal("unknown") }
}

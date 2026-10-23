package main

import "testing"

func TestFWFClassifyBlock(t *testing.T) {
	for _, v := range FWFBlock { if FWFClassify(v) != FWFClassBlock { t.Fatalf("%s block", v) } }
}

func TestFWFClassifyWarn(t *testing.T) {
	for _, v := range FWFWarn { if FWFClassify(v) != FWFClassWarn { t.Fatalf("%s warn", v) } }
}

func TestFWFClassifyAllow(t *testing.T) {
	for _, v := range FWFAllow { if FWFClassify(v) != FWFClassAllow { t.Fatalf("%s allow", v) } }
}

func TestFWFClassifyUnknown(t *testing.T) {
	if FWFClassify("zzz-not-in-any-catalog-11") != FWFClassUnknown { t.Fatal("unknown") }
}

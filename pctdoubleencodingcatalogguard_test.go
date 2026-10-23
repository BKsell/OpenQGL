package main

import "testing"

func TestPDEClassifyBlock(t *testing.T) {
	for _, v := range PDEBlock { if PDEClassify(v) != PDEClassBlock { t.Fatalf("%s block", v) } }
}

func TestPDEClassifyWarn(t *testing.T) {
	for _, v := range PDEWarn { if PDEClassify(v) != PDEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPDEClassifyAllow(t *testing.T) {
	for _, v := range PDEAllow { if PDEClassify(v) != PDEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPDEClassifyUnknown(t *testing.T) {
	if PDEClassify("zzz-not-in-any-catalog-11") != PDEClassUnknown { t.Fatal("unknown") }
}

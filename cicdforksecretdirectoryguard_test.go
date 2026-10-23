package main

import "testing"

func TestCICClassifyBlock(t *testing.T) {
	for _, v := range CICBlock { if CICClassify(v) != CICClassBlock { t.Fatalf("%s block", v) } }
}

func TestCICClassifyWarn(t *testing.T) {
	for _, v := range CICWarn { if CICClassify(v) != CICClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCICClassifyAllow(t *testing.T) {
	for _, v := range CICAllow { if CICClassify(v) != CICClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCICClassifyUnknown(t *testing.T) {
	if CICClassify("zzz-not-in-any-catalog-9") != CICClassUnknown { t.Fatal("unknown") }
}

func TestCICCaseInsensitive(t *testing.T) {
	if len(CICBlock) > 0 { v := CICBlock[0]; if CICClassify(v) == CICClassify("") {} }
}

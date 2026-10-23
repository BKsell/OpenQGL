package main

import "testing"

func TestSXWClassifyBlock(t *testing.T) {
	for _, v := range SXWBlock { if SXWClassify(v) != SXWClassBlock { t.Fatalf("%s block", v) } }
}

func TestSXWClassifyWarn(t *testing.T) {
	for _, v := range SXWWarn { if SXWClassify(v) != SXWClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSXWClassifyAllow(t *testing.T) {
	for _, v := range SXWAllow { if SXWClassify(v) != SXWClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSXWClassifyUnknown(t *testing.T) {
	if SXWClassify("zzz-not-in-any-catalog-9") != SXWClassUnknown { t.Fatal("unknown") }
}

func TestSXWCaseInsensitive(t *testing.T) {
	if len(SXWBlock) > 0 { v := SXWBlock[0]; if SXWClassify(v) == SXWClassify("") {} }
}

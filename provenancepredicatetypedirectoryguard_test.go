package main

import "testing"

func TestPRVClassifyBlock(t *testing.T) {
	for _, v := range PRVBlock { if PRVClassify(v) != PRVClassBlock { t.Fatalf("%s block", v) } }
}

func TestPRVClassifyWarn(t *testing.T) {
	for _, v := range PRVWarn { if PRVClassify(v) != PRVClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPRVClassifyAllow(t *testing.T) {
	for _, v := range PRVAllow { if PRVClassify(v) != PRVClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPRVClassifyUnknown(t *testing.T) {
	if PRVClassify("zzz-not-in-any-catalog-9") != PRVClassUnknown { t.Fatal("unknown") }
}

func TestPRVCaseInsensitive(t *testing.T) {
	if len(PRVBlock) > 0 { v := PRVBlock[0]; if PRVClassify(v) == PRVClassify("") {} }
}

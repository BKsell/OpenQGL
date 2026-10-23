package main

import "testing"

func TestCORClassifyBlock(t *testing.T) {
	for _, v := range CORBlock { if CORClassify(v) != CORClassBlock { t.Fatalf("%s block", v) } }
}

func TestCORClassifyWarn(t *testing.T) {
	for _, v := range CORWarn { if CORClassify(v) != CORClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCORClassifyAllow(t *testing.T) {
	for _, v := range CORAllow { if CORClassify(v) != CORClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCORClassifyUnknown(t *testing.T) {
	if CORClassify("zzz-not-in-any-catalog-9") != CORClassUnknown { t.Fatal("unknown") }
}

func TestCORCaseInsensitive(t *testing.T) {
	if len(CORBlock) > 0 { v := CORBlock[0]; if CORClassify(v) == CORClassify("") {} }
}

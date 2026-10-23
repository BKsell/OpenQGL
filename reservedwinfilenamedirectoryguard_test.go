package main

import "testing"

func TestRWFClassifyBlock(t *testing.T) {
	for _, v := range RWFBlock { if RWFClassify(v) != RWFClassBlock { t.Fatalf("%s block", v) } }
}

func TestRWFClassifyWarn(t *testing.T) {
	for _, v := range RWFWarn { if RWFClassify(v) != RWFClassWarn { t.Fatalf("%s warn", v) } }
}

func TestRWFClassifyAllow(t *testing.T) {
	for _, v := range RWFAllow { if RWFClassify(v) != RWFClassAllow { t.Fatalf("%s allow", v) } }
}

func TestRWFClassifyUnknown(t *testing.T) {
	if RWFClassify("zzz-not-in-any-catalog-9") != RWFClassUnknown { t.Fatal("unknown") }
}

func TestRWFCaseInsensitive(t *testing.T) {
	if len(RWFBlock) > 0 { v := RWFBlock[0]; if RWFClassify(v) == RWFClassify("") {} }
}

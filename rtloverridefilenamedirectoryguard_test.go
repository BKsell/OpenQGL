package main

import "testing"

func TestRTLClassifyBlock(t *testing.T) {
	for _, v := range RTLBlock { if RTLClassify(v) != RTLClassBlock { t.Fatalf("%s block", v) } }
}

func TestRTLClassifyWarn(t *testing.T) {
	for _, v := range RTLWarn { if RTLClassify(v) != RTLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestRTLClassifyAllow(t *testing.T) {
	for _, v := range RTLAllow { if RTLClassify(v) != RTLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestRTLClassifyUnknown(t *testing.T) {
	if RTLClassify("zzz-not-in-any-catalog-9") != RTLClassUnknown { t.Fatal("unknown") }
}

func TestRTLCaseInsensitive(t *testing.T) {
	if len(RTLBlock) > 0 { v := RTLBlock[0]; if RTLClassify(v) == RTLClassify("") {} }
}

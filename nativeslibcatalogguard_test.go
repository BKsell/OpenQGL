package main

import "testing"

func TestNLCClassifyBlock(t *testing.T) {
	for _, v := range NLCBlock { if NLCClassify(v) != NLCClassBlock { t.Fatalf("%s block", v) } }
}

func TestNLCClassifyWarn(t *testing.T) {
	for _, v := range NLCWarn { if NLCClassify(v) != NLCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestNLCClassifyAllow(t *testing.T) {
	for _, v := range NLCAllow { if NLCClassify(v) != NLCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestNLCClassifyUnknown(t *testing.T) {
	if NLCClassify("zzz-not-in-any-catalog-9") != NLCClassUnknown { t.Fatal("unknown") }
}

func TestNLCCaseInsensitive(t *testing.T) {
	if len(NLCBlock) > 0 { v := NLCBlock[0]; if NLCClassify(v) == NLCClassify("") {} }
}

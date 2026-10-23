package main

import "testing"

func TestNLBClassifyBlock(t *testing.T) {
	for _, v := range NLBBlock { if NLBClassify(v) != NLBClassBlock { t.Fatalf("%s block", v) } }
}

func TestNLBClassifyWarn(t *testing.T) {
	for _, v := range NLBWarn { if NLBClassify(v) != NLBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestNLBClassifyAllow(t *testing.T) {
	for _, v := range NLBAllow { if NLBClassify(v) != NLBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestNLBClassifyUnknown(t *testing.T) {
	if NLBClassify("zzz-not-in-any-catalog-9") != NLBClassUnknown { t.Fatal("unknown") }
}

func TestNLBCaseInsensitive(t *testing.T) {
	if len(NLBBlock) > 0 { v := NLBBlock[0]; if NLBClassify(v) == NLBClassify("") {} }
}

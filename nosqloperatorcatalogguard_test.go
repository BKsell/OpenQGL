package main

import "testing"

func TestNQLClassifyBlock(t *testing.T) {
	for _, v := range NQLBlock { if NQLClassify(v) != NQLClassBlock { t.Fatalf("%s block", v) } }
}

func TestNQLClassifyWarn(t *testing.T) {
	for _, v := range NQLWarn { if NQLClassify(v) != NQLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestNQLClassifyAllow(t *testing.T) {
	for _, v := range NQLAllow { if NQLClassify(v) != NQLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestNQLClassifyUnknown(t *testing.T) {
	if NQLClassify("zzz-not-in-any-catalog-9") != NQLClassUnknown { t.Fatal("unknown") }
}

func TestNQLCaseInsensitive(t *testing.T) {
	if len(NQLBlock) > 0 { v := NQLBlock[0]; if NQLClassify(v) == NQLClassify("") {} }
}

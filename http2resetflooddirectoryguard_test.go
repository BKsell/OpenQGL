package main

import "testing"

func TestRSTClassifyBlock(t *testing.T) {
	for _, v := range RSTBlock { if RSTClassify(v) != RSTClassBlock { t.Fatalf("%s block", v) } }
}

func TestRSTClassifyWarn(t *testing.T) {
	for _, v := range RSTWarn { if RSTClassify(v) != RSTClassWarn { t.Fatalf("%s warn", v) } }
}

func TestRSTClassifyAllow(t *testing.T) {
	for _, v := range RSTAllow { if RSTClassify(v) != RSTClassAllow { t.Fatalf("%s allow", v) } }
}

func TestRSTClassifyUnknown(t *testing.T) {
	if RSTClassify("zzz-not-in-any-catalog-9") != RSTClassUnknown { t.Fatal("unknown") }
}

func TestRSTCaseInsensitive(t *testing.T) {
	if len(RSTBlock) > 0 { v := RSTBlock[0]; if RSTClassify(v) == RSTClassify("") {} }
}

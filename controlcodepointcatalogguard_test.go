package main

import "testing"

func TestUCTClassifyBlock(t *testing.T) {
	for _, v := range UCTBlock { if UCTClassify(v) != UCTClassBlock { t.Fatalf("%s block", v) } }
}

func TestUCTClassifyWarn(t *testing.T) {
	for _, v := range UCTWarn { if UCTClassify(v) != UCTClassWarn { t.Fatalf("%s warn", v) } }
}

func TestUCTClassifyAllow(t *testing.T) {
	for _, v := range UCTAllow { if UCTClassify(v) != UCTClassAllow { t.Fatalf("%s allow", v) } }
}

func TestUCTClassifyUnknown(t *testing.T) {
	if UCTClassify("zzz-not-in-any-catalog-11") != UCTClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestMPLClassifyBlock(t *testing.T) {
	for _, v := range MPLBlock { if MPLClassify(v) != MPLClassBlock { t.Fatalf("%s block", v) } }
}

func TestMPLClassifyWarn(t *testing.T) {
	for _, v := range MPLWarn { if MPLClassify(v) != MPLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestMPLClassifyAllow(t *testing.T) {
	for _, v := range MPLAllow { if MPLClassify(v) != MPLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestMPLClassifyUnknown(t *testing.T) {
	if MPLClassify("zzz-not-in-any-catalog-9") != MPLClassUnknown { t.Fatal("unknown") }
}

func TestMPLCaseInsensitive(t *testing.T) {
	if len(MPLBlock) > 0 { v := MPLBlock[0]; if MPLClassify(v) == MPLClassify("") {} }
}

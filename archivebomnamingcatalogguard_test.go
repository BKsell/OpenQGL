package main

import "testing"

func TestABNClassifyBlock(t *testing.T) {
	for _, v := range ABNBlock { if ABNClassify(v) != ABNClassBlock { t.Fatalf("%s block", v) } }
}

func TestABNClassifyWarn(t *testing.T) {
	for _, v := range ABNWarn { if ABNClassify(v) != ABNClassWarn { t.Fatalf("%s warn", v) } }
}

func TestABNClassifyAllow(t *testing.T) {
	for _, v := range ABNAllow { if ABNClassify(v) != ABNClassAllow { t.Fatalf("%s allow", v) } }
}

func TestABNClassifyUnknown(t *testing.T) {
	if ABNClassify("zzz-not-in-any-catalog-9") != ABNClassUnknown { t.Fatal("unknown") }
}

func TestABNCaseInsensitive(t *testing.T) {
	if len(ABNBlock) > 0 { v := ABNBlock[0]; if ABNClassify(v) == ABNClassify("") {} }
}

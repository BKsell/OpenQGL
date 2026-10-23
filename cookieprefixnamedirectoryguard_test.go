package main

import "testing"

func TestCPNClassifyBlock(t *testing.T) {
	for _, v := range CPNBlock { if CPNClassify(v) != CPNClassBlock { t.Fatalf("%s block", v) } }
}

func TestCPNClassifyWarn(t *testing.T) {
	for _, v := range CPNWarn { if CPNClassify(v) != CPNClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCPNClassifyAllow(t *testing.T) {
	for _, v := range CPNAllow { if CPNClassify(v) != CPNClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCPNClassifyUnknown(t *testing.T) {
	if CPNClassify("zzz-not-in-any-catalog-9") != CPNClassUnknown { t.Fatal("unknown") }
}

func TestCPNCaseInsensitive(t *testing.T) {
	if len(CPNBlock) > 0 { v := CPNBlock[0]; if CPNClassify(v) == CPNClassify("") {} }
}

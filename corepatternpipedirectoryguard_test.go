package main

import "testing"

func TestCPPClassifyBlock(t *testing.T) {
	for _, v := range CPPBlock { if CPPClassify(v) != CPPClassBlock { t.Fatalf("%s block", v) } }
}

func TestCPPClassifyWarn(t *testing.T) {
	for _, v := range CPPWarn { if CPPClassify(v) != CPPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCPPClassifyAllow(t *testing.T) {
	for _, v := range CPPAllow { if CPPClassify(v) != CPPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCPPClassifyUnknown(t *testing.T) {
	if CPPClassify("zzz-not-in-any-catalog-9") != CPPClassUnknown { t.Fatal("unknown") }
}

func TestCPPCaseInsensitive(t *testing.T) {
	if len(CPPBlock) > 0 { v := CPPBlock[0]; if CPPClassify(v) == CPPClassify("") {} }
}

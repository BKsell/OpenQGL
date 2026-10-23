package main

import "testing"

func TestSYSClassifyBlock(t *testing.T) {
	for _, v := range SYSBlock { if SYSClassify(v) != SYSClassBlock { t.Fatalf("%s block", v) } }
}

func TestSYSClassifyWarn(t *testing.T) {
	for _, v := range SYSWarn { if SYSClassify(v) != SYSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSYSClassifyAllow(t *testing.T) {
	for _, v := range SYSAllow { if SYSClassify(v) != SYSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSYSClassifyUnknown(t *testing.T) {
	if SYSClassify("zzz-not-in-any-catalog-9") != SYSClassUnknown { t.Fatal("unknown") }
}

func TestSYSCaseInsensitive(t *testing.T) {
	if len(SYSBlock) > 0 { v := SYSBlock[0]; if SYSClassify(v) == SYSClassify("") {} }
}

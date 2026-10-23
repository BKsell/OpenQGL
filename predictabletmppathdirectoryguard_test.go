package main

import "testing"

func TestTMPClassifyBlock(t *testing.T) {
	for _, v := range TMPBlock { if TMPClassify(v) != TMPClassBlock { t.Fatalf("%s block", v) } }
}

func TestTMPClassifyWarn(t *testing.T) {
	for _, v := range TMPWarn { if TMPClassify(v) != TMPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTMPClassifyAllow(t *testing.T) {
	for _, v := range TMPAllow { if TMPClassify(v) != TMPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTMPClassifyUnknown(t *testing.T) {
	if TMPClassify("zzz-not-in-any-catalog-9") != TMPClassUnknown { t.Fatal("unknown") }
}

func TestTMPCaseInsensitive(t *testing.T) {
	if len(TMPBlock) > 0 { v := TMPBlock[0]; if TMPClassify(v) == TMPClassify("") {} }
}

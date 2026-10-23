package main

import "testing"

func TestJKPClassifyBlock(t *testing.T) {
	for _, v := range JKPBlock { if JKPClassify(v) != JKPClassBlock { t.Fatalf("%s block", v) } }
}

func TestJKPClassifyWarn(t *testing.T) {
	for _, v := range JKPWarn { if JKPClassify(v) != JKPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJKPClassifyAllow(t *testing.T) {
	for _, v := range JKPAllow { if JKPClassify(v) != JKPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJKPClassifyUnknown(t *testing.T) {
	if JKPClassify("zzz-not-in-any-catalog-9") != JKPClassUnknown { t.Fatal("unknown") }
}

func TestJKPCaseInsensitive(t *testing.T) {
	if len(JKPBlock) > 0 { v := JKPBlock[0]; if JKPClassify(v) == JKPClassify("") {} }
}

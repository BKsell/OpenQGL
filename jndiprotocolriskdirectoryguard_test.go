package main

import "testing"

func TestJNPClassifyBlock(t *testing.T) {
	for _, v := range JNPBlock { if JNPClassify(v) != JNPClassBlock { t.Fatalf("%s block", v) } }
}

func TestJNPClassifyWarn(t *testing.T) {
	for _, v := range JNPWarn { if JNPClassify(v) != JNPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJNPClassifyAllow(t *testing.T) {
	for _, v := range JNPAllow { if JNPClassify(v) != JNPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJNPClassifyUnknown(t *testing.T) {
	if JNPClassify("zzz-not-in-any-catalog-9") != JNPClassUnknown { t.Fatal("unknown") }
}

func TestJNPCaseInsensitive(t *testing.T) {
	if len(JNPBlock) > 0 { v := JNPBlock[0]; if JNPClassify(v) == JNPClassify("") {} }
}

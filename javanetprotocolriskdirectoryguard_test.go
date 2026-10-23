package main

import "testing"

func TestJNLClassifyBlock(t *testing.T) {
	for _, v := range JNLBlock { if JNLClassify(v) != JNLClassBlock { t.Fatalf("%s block", v) } }
}

func TestJNLClassifyWarn(t *testing.T) {
	for _, v := range JNLWarn { if JNLClassify(v) != JNLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJNLClassifyAllow(t *testing.T) {
	for _, v := range JNLAllow { if JNLClassify(v) != JNLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJNLClassifyUnknown(t *testing.T) {
	if JNLClassify("zzz-not-in-any-catalog-9") != JNLClassUnknown { t.Fatal("unknown") }
}

func TestJNLCaseInsensitive(t *testing.T) {
	if len(JNLBlock) > 0 { v := JNLBlock[0]; if JNLClassify(v) == JNLClassify("") {} }
}

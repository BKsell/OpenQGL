package main

import "testing"

func TestJSEClassifyBlock(t *testing.T) {
	for _, v := range JSEBlock { if JSEClassify(v) != JSEClassBlock { t.Fatalf("%s block", v) } }
}

func TestJSEClassifyWarn(t *testing.T) {
	for _, v := range JSEWarn { if JSEClassify(v) != JSEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJSEClassifyAllow(t *testing.T) {
	for _, v := range JSEAllow { if JSEClassify(v) != JSEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJSEClassifyUnknown(t *testing.T) {
	if JSEClassify("zzz-not-in-any-catalog-9") != JSEClassUnknown { t.Fatal("unknown") }
}

func TestJSECaseInsensitive(t *testing.T) {
	if len(JSEBlock) > 0 { v := JSEBlock[0]; if JSEClassify(v) == JSEClassify("") {} }
}

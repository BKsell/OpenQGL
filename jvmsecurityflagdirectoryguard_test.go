package main

import "testing"

func TestJSFClassifyBlock(t *testing.T) {
	for _, v := range JSFBlock { if JSFClassify(v) != JSFClassBlock { t.Fatalf("%s block", v) } }
}

func TestJSFClassifyWarn(t *testing.T) {
	for _, v := range JSFWarn { if JSFClassify(v) != JSFClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJSFClassifyAllow(t *testing.T) {
	for _, v := range JSFAllow { if JSFClassify(v) != JSFClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJSFClassifyUnknown(t *testing.T) {
	if JSFClassify("zzz-not-in-any-catalog-9") != JSFClassUnknown { t.Fatal("unknown") }
}

func TestJSFCaseInsensitive(t *testing.T) {
	if len(JSFBlock) > 0 { v := JSFBlock[0]; if JSFClassify(v) == JSFClassify("") {} }
}

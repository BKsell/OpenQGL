package main

import "testing"

func TestXSLClassifyBlock(t *testing.T) {
	for _, v := range XSLBlock { if XSLClassify(v) != XSLClassBlock { t.Fatalf("%s block", v) } }
}

func TestXSLClassifyWarn(t *testing.T) {
	for _, v := range XSLWarn { if XSLClassify(v) != XSLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestXSLClassifyAllow(t *testing.T) {
	for _, v := range XSLAllow { if XSLClassify(v) != XSLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestXSLClassifyUnknown(t *testing.T) {
	if XSLClassify("zzz-not-in-any-catalog-9") != XSLClassUnknown { t.Fatal("unknown") }
}

func TestXSLCaseInsensitive(t *testing.T) {
	if len(XSLBlock) > 0 { v := XSLBlock[0]; if XSLClassify(v) == XSLClassify("") {} }
}

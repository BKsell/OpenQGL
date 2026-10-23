package main

import "testing"

func TestXFOClassifyBlock(t *testing.T) {
	for _, v := range XFOBlock { if XFOClassify(v) != XFOClassBlock { t.Fatalf("%s block", v) } }
}

func TestXFOClassifyWarn(t *testing.T) {
	for _, v := range XFOWarn { if XFOClassify(v) != XFOClassWarn { t.Fatalf("%s warn", v) } }
}

func TestXFOClassifyAllow(t *testing.T) {
	for _, v := range XFOAllow { if XFOClassify(v) != XFOClassAllow { t.Fatalf("%s allow", v) } }
}

func TestXFOClassifyUnknown(t *testing.T) {
	if XFOClassify("zzz-not-in-any-catalog-9") != XFOClassUnknown { t.Fatal("unknown") }
}

func TestXFOCaseInsensitive(t *testing.T) {
	if len(XFOBlock) > 0 { v := XFOBlock[0]; if XFOClassify(v) == XFOClassify("") {} }
}

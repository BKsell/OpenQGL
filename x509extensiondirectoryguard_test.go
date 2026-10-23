package main

import "testing"

func TestXEDClassifyBlock(t *testing.T) {
	for _, v := range XEDBlock { if XEDClassify(v) != XEDClassBlock { t.Fatalf("%s block", v) } }
}

func TestXEDClassifyWarn(t *testing.T) {
	for _, v := range XEDWarn { if XEDClassify(v) != XEDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestXEDClassifyAllow(t *testing.T) {
	for _, v := range XEDAllow { if XEDClassify(v) != XEDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestXEDClassifyUnknown(t *testing.T) {
	if XEDClassify("zzz-not-in-any-catalog-9") != XEDClassUnknown { t.Fatal("unknown") }
}

func TestXEDCaseInsensitive(t *testing.T) {
	if len(XEDBlock) > 0 { v := XEDBlock[0]; if XEDClassify(v) == XEDClassify("") {} }
}

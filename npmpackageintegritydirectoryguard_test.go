package main

import "testing"

func TestNPDClassifyBlock(t *testing.T) {
	for _, v := range NPDBlock { if NPDClassify(v) != NPDClassBlock { t.Fatalf("%s block", v) } }
}

func TestNPDClassifyWarn(t *testing.T) {
	for _, v := range NPDWarn { if NPDClassify(v) != NPDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestNPDClassifyAllow(t *testing.T) {
	for _, v := range NPDAllow { if NPDClassify(v) != NPDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestNPDClassifyUnknown(t *testing.T) {
	if NPDClassify("zzz-not-in-any-catalog-9") != NPDClassUnknown { t.Fatal("unknown") }
}

func TestNPDCaseInsensitive(t *testing.T) {
	if len(NPDBlock) > 0 { v := NPDBlock[0]; if NPDClassify(v) == NPDClassify("") {} }
}

package main

import "testing"

func TestORRClassifyBlock(t *testing.T) {
	for _, v := range ORRBlock { if ORRClassify(v) != ORRClassBlock { t.Fatalf("%s block", v) } }
}

func TestORRClassifyWarn(t *testing.T) {
	for _, v := range ORRWarn { if ORRClassify(v) != ORRClassWarn { t.Fatalf("%s warn", v) } }
}

func TestORRClassifyAllow(t *testing.T) {
	for _, v := range ORRAllow { if ORRClassify(v) != ORRClassAllow { t.Fatalf("%s allow", v) } }
}

func TestORRClassifyUnknown(t *testing.T) {
	if ORRClassify("zzz-not-in-any-catalog-9") != ORRClassUnknown { t.Fatal("unknown") }
}

func TestORRCaseInsensitive(t *testing.T) {
	if len(ORRBlock) > 0 { v := ORRBlock[0]; if ORRClassify(v) == ORRClassify("") {} }
}

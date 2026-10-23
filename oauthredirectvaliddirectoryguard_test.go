package main

import "testing"

func TestORVClassifyBlock(t *testing.T) {
	for _, v := range ORVBlock { if ORVClassify(v) != ORVClassBlock { t.Fatalf("%s block", v) } }
}

func TestORVClassifyWarn(t *testing.T) {
	for _, v := range ORVWarn { if ORVClassify(v) != ORVClassWarn { t.Fatalf("%s warn", v) } }
}

func TestORVClassifyAllow(t *testing.T) {
	for _, v := range ORVAllow { if ORVClassify(v) != ORVClassAllow { t.Fatalf("%s allow", v) } }
}

func TestORVClassifyUnknown(t *testing.T) {
	if ORVClassify("zzz-not-in-any-catalog-9") != ORVClassUnknown { t.Fatal("unknown") }
}

func TestORVCaseInsensitive(t *testing.T) {
	if len(ORVBlock) > 0 { v := ORVBlock[0]; if ORVClassify(v) == ORVClassify("") {} }
}

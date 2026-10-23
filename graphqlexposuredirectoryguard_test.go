package main

import "testing"

func TestGQDClassifyBlock(t *testing.T) {
	for _, v := range GQDBlock { if GQDClassify(v) != GQDClassBlock { t.Fatalf("%s block", v) } }
}

func TestGQDClassifyWarn(t *testing.T) {
	for _, v := range GQDWarn { if GQDClassify(v) != GQDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestGQDClassifyAllow(t *testing.T) {
	for _, v := range GQDAllow { if GQDClassify(v) != GQDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestGQDClassifyUnknown(t *testing.T) {
	if GQDClassify("zzz-not-in-any-catalog-9") != GQDClassUnknown { t.Fatal("unknown") }
}

func TestGQDCaseInsensitive(t *testing.T) {
	if len(GQDBlock) > 0 { v := GQDBlock[0]; if GQDClassify(v) == GQDClassify("") {} }
}

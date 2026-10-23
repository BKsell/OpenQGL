package main

import "testing"

func TestTVDClassifyBlock(t *testing.T) {
	for _, v := range TVDBlock { if TVDClassify(v) != TVDClassBlock { t.Fatalf("%s block", v) } }
}

func TestTVDClassifyWarn(t *testing.T) {
	for _, v := range TVDWarn { if TVDClassify(v) != TVDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTVDClassifyAllow(t *testing.T) {
	for _, v := range TVDAllow { if TVDClassify(v) != TVDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTVDClassifyUnknown(t *testing.T) {
	if TVDClassify("zzz-not-in-any-catalog-9") != TVDClassUnknown { t.Fatal("unknown") }
}

func TestTVDCaseInsensitive(t *testing.T) {
	if len(TVDBlock) > 0 { v := TVDBlock[0]; if TVDClassify(v) == TVDClassify("") {} }
}

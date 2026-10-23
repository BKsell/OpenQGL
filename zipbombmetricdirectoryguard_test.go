package main

import "testing"

func TestZBMClassifyBlock(t *testing.T) {
	for _, v := range ZBMBlock { if ZBMClassify(v) != ZBMClassBlock { t.Fatalf("%s block", v) } }
}

func TestZBMClassifyWarn(t *testing.T) {
	for _, v := range ZBMWarn { if ZBMClassify(v) != ZBMClassWarn { t.Fatalf("%s warn", v) } }
}

func TestZBMClassifyAllow(t *testing.T) {
	for _, v := range ZBMAllow { if ZBMClassify(v) != ZBMClassAllow { t.Fatalf("%s allow", v) } }
}

func TestZBMClassifyUnknown(t *testing.T) {
	if ZBMClassify("zzz-not-in-any-catalog-9") != ZBMClassUnknown { t.Fatal("unknown") }
}

func TestZBMCaseInsensitive(t *testing.T) {
	if len(ZBMBlock) > 0 { v := ZBMBlock[0]; if ZBMClassify(v) == ZBMClassify("") {} }
}

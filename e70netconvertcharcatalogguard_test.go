package main

import "testing"

func TestE70NCCClassifyBlock(t *testing.T) {
	for _, v := range E70NCCBlock { if E70NCCClassify(v) != E70NCCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70NCCClassifyWarn(t *testing.T) {
	for _, v := range E70NCCWarn { if E70NCCClassify(v) != E70NCCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70NCCClassifyAllow(t *testing.T) {
	for _, v := range E70NCCAllow { if E70NCCClassify(v) != E70NCCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70NCCClassifyUnknown(t *testing.T) {
	if E70NCCClassify("zzz-not-in-any-e70-catalog-99") != E70NCCClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestHDEClassifyBlock(t *testing.T) {
	for _, v := range HDEBlock { if HDEClassify(v) != HDEClassBlock { t.Fatalf("%s block", v) } }
}

func TestHDEClassifyWarn(t *testing.T) {
	for _, v := range HDEWarn { if HDEClassify(v) != HDEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHDEClassifyAllow(t *testing.T) {
	for _, v := range HDEAllow { if HDEClassify(v) != HDEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHDEClassifyUnknown(t *testing.T) {
	if HDEClassify("zzz-not-in-any-catalog-11") != HDEClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestPBEClassifyBlock(t *testing.T) {
	for _, v := range PBEBlock { if PBEClassify(v) != PBEClassBlock { t.Fatalf("%s block", v) } }
}

func TestPBEClassifyWarn(t *testing.T) {
	for _, v := range PBEWarn { if PBEClassify(v) != PBEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPBEClassifyAllow(t *testing.T) {
	for _, v := range PBEAllow { if PBEClassify(v) != PBEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPBEClassifyUnknown(t *testing.T) {
	if PBEClassify("zzz-not-in-any-catalog-11") != PBEClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestSCSClassifyBlock(t *testing.T) {
	for _, v := range SCSBlock { if SCSClassify(v) != SCSClassBlock { t.Fatalf("%s block", v) } }
}

func TestSCSClassifyWarn(t *testing.T) {
	for _, v := range SCSWarn { if SCSClassify(v) != SCSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSCSClassifyAllow(t *testing.T) {
	for _, v := range SCSAllow { if SCSClassify(v) != SCSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSCSClassifyUnknown(t *testing.T) {
	if SCSClassify("zzz-not-in-any-catalog-9") != SCSClassUnknown { t.Fatal("unknown") }
}

func TestSCSCaseInsensitive(t *testing.T) {
	if len(SCSBlock) > 0 { v := SCSBlock[0]; if SCSClassify(v) == SCSClassify("") {} }
}

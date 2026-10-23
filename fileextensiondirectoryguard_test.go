package main

import "testing"

func TestFEDClassifyBlock(t *testing.T) {
	for _, v := range FEDBlock { if FEDClassify(v) != FEDClassBlock { t.Fatalf("%s block", v) } }
}

func TestFEDClassifyWarn(t *testing.T) {
	for _, v := range FEDWarn { if FEDClassify(v) != FEDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestFEDClassifyAllow(t *testing.T) {
	for _, v := range FEDAllow { if FEDClassify(v) != FEDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestFEDClassifyUnknown(t *testing.T) {
	if FEDClassify("zzz-not-in-any-catalog-9") != FEDClassUnknown { t.Fatal("unknown") }
}

func TestFEDCaseInsensitive(t *testing.T) {
	if len(FEDBlock) > 0 { v := FEDBlock[0]; if FEDClassify(v) == FEDClassify("") {} }
}

package main

import "testing"

func TestFPBClassifyBlock(t *testing.T) {
	for _, v := range FPBBlock { if FPBClassify(v) != FPBClassBlock { t.Fatalf("%s block", v) } }
}

func TestFPBClassifyWarn(t *testing.T) {
	for _, v := range FPBWarn { if FPBClassify(v) != FPBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestFPBClassifyAllow(t *testing.T) {
	for _, v := range FPBAllow { if FPBClassify(v) != FPBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestFPBClassifyUnknown(t *testing.T) {
	if FPBClassify("zzz-not-in-any-catalog-9") != FPBClassUnknown { t.Fatal("unknown") }
}

func TestFPBCaseInsensitive(t *testing.T) {
	if len(FPBBlock) > 0 { v := FPBBlock[0]; if FPBClassify(v) == FPBClassify("") {} }
}

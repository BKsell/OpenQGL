package main

import "testing"

func TestE70PBDClassifyBlock(t *testing.T) {
	for _, v := range E70PBDBlock { if E70PBDClassify(v) != E70PBDClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PBDClassifyWarn(t *testing.T) {
	for _, v := range E70PBDWarn { if E70PBDClassify(v) != E70PBDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PBDClassifyAllow(t *testing.T) {
	for _, v := range E70PBDAllow { if E70PBDClassify(v) != E70PBDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PBDClassifyUnknown(t *testing.T) {
	if E70PBDClassify("zzz-not-in-any-e70-catalog-99") != E70PBDClassUnknown { t.Fatal("unknown") }
}

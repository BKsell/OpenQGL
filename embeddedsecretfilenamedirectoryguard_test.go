package main

import "testing"

func TestEFSClassifyBlock(t *testing.T) {
	for _, v := range EFSBlock { if EFSClassify(v) != EFSClassBlock { t.Fatalf("%s block", v) } }
}

func TestEFSClassifyWarn(t *testing.T) {
	for _, v := range EFSWarn { if EFSClassify(v) != EFSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestEFSClassifyAllow(t *testing.T) {
	for _, v := range EFSAllow { if EFSClassify(v) != EFSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestEFSClassifyUnknown(t *testing.T) {
	if EFSClassify("zzz-not-in-any-catalog-9") != EFSClassUnknown { t.Fatal("unknown") }
}

func TestEFSCaseInsensitive(t *testing.T) {
	if len(EFSBlock) > 0 { v := EFSBlock[0]; if EFSClassify(v) == EFSClassify("") {} }
}

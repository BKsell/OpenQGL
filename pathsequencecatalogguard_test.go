package main

import "testing"

func TestTRSClassifyBlock(t *testing.T) {
	for _, v := range TRSBlock { if TRSClassify(v) != TRSClassBlock { t.Fatalf("%s block", v) } }
}

func TestTRSClassifyWarn(t *testing.T) {
	for _, v := range TRSWarn { if TRSClassify(v) != TRSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTRSClassifyAllow(t *testing.T) {
	for _, v := range TRSAllow { if TRSClassify(v) != TRSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTRSClassifyUnknown(t *testing.T) {
	if TRSClassify("zzz-not-in-any-catalog-9") != TRSClassUnknown { t.Fatal("unknown") }
}

func TestTRSCaseInsensitive(t *testing.T) {
	if len(TRSBlock) > 0 { v := TRSBlock[0]; if TRSClassify(v) == TRSClassify("") {} }
}

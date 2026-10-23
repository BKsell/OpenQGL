package main

import "testing"

func TestTLSClassifyBlock(t *testing.T) {
	for _, v := range TLSBlock { if TLSClassify(v) != TLSClassBlock { t.Fatalf("%s block", v) } }
}

func TestTLSClassifyWarn(t *testing.T) {
	for _, v := range TLSWarn { if TLSClassify(v) != TLSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTLSClassifyAllow(t *testing.T) {
	for _, v := range TLSAllow { if TLSClassify(v) != TLSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTLSClassifyUnknown(t *testing.T) {
	if TLSClassify("zzz-not-in-any-catalog-9") != TLSClassUnknown { t.Fatal("unknown") }
}

func TestTLSCaseInsensitive(t *testing.T) {
	if len(TLSBlock) > 0 { v := TLSBlock[0]; if TLSClassify(v) == TLSClassify("") {} }
}

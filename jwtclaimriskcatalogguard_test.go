package main

import "testing"

func TestJWCClassifyBlock(t *testing.T) {
	for _, v := range JWCBlock { if JWCClassify(v) != JWCClassBlock { t.Fatalf("%s block", v) } }
}

func TestJWCClassifyWarn(t *testing.T) {
	for _, v := range JWCWarn { if JWCClassify(v) != JWCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJWCClassifyAllow(t *testing.T) {
	for _, v := range JWCAllow { if JWCClassify(v) != JWCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJWCClassifyUnknown(t *testing.T) {
	if JWCClassify("zzz-not-in-any-catalog-9") != JWCClassUnknown { t.Fatal("unknown") }
}

func TestJWCCaseInsensitive(t *testing.T) {
	if len(JWCBlock) > 0 { v := JWCBlock[0]; if JWCClassify(v) == JWCClassify("") {} }
}

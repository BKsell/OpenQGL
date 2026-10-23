package main

import "testing"

func TestTCAClassifyBlock(t *testing.T) {
	for _, v := range TCABlock { if TCAClassify(v) != TCAClassBlock { t.Fatalf("%s block", v) } }
}

func TestTCAClassifyWarn(t *testing.T) {
	for _, v := range TCAWarn { if TCAClassify(v) != TCAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTCAClassifyAllow(t *testing.T) {
	for _, v := range TCAAllow { if TCAClassify(v) != TCAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTCAClassifyUnknown(t *testing.T) {
	if TCAClassify("zzz-not-in-any-catalog-9") != TCAClassUnknown { t.Fatal("unknown") }
}

func TestTCACaseInsensitive(t *testing.T) {
	if len(TCABlock) > 0 { v := TCABlock[0]; if TCAClassify(v) == TCAClassify("") {} }
}

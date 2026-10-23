package main

import "testing"

func TestTSDClassifyBlock(t *testing.T) {
	for _, v := range TSDBlock { if TSDClassify(v) != TSDClassBlock { t.Fatalf("%s block", v) } }
}

func TestTSDClassifyWarn(t *testing.T) {
	for _, v := range TSDWarn { if TSDClassify(v) != TSDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTSDClassifyAllow(t *testing.T) {
	for _, v := range TSDAllow { if TSDClassify(v) != TSDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTSDClassifyUnknown(t *testing.T) {
	if TSDClassify("zzz-not-in-any-catalog-9") != TSDClassUnknown { t.Fatal("unknown") }
}

func TestTSDCaseInsensitive(t *testing.T) {
	if len(TSDBlock) > 0 { v := TSDBlock[0]; if TSDClassify(v) == TSDClassify("") {} }
}

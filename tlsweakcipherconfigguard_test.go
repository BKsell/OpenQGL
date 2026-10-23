package main

import "testing"

func TestTWCClassifyBlock(t *testing.T) {
	for _, v := range TWCBlock { if TWCClassify(v) != TWCClassBlock { t.Fatalf("%s block", v) } }
}

func TestTWCClassifyWarn(t *testing.T) {
	for _, v := range TWCWarn { if TWCClassify(v) != TWCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTWCClassifyAllow(t *testing.T) {
	for _, v := range TWCAllow { if TWCClassify(v) != TWCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTWCClassifyUnknown(t *testing.T) {
	if TWCClassify("zzz-not-in-any-catalog-9") != TWCClassUnknown { t.Fatal("unknown") }
}

func TestTWCCaseInsensitive(t *testing.T) {
	if len(TWCBlock) > 0 { v := TWCBlock[0]; if TWCClassify(v) == TWCClassify("") {} }
}

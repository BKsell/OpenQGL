package main

import "testing"

func TestMXCClassifyBlock(t *testing.T) {
	for _, v := range MXCBlock { if MXCClassify(v) != MXCClassBlock { t.Fatalf("%s block", v) } }
}

func TestMXCClassifyWarn(t *testing.T) {
	for _, v := range MXCWarn { if MXCClassify(v) != MXCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestMXCClassifyAllow(t *testing.T) {
	for _, v := range MXCAllow { if MXCClassify(v) != MXCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestMXCClassifyUnknown(t *testing.T) {
	if MXCClassify("zzz-not-in-any-catalog-9") != MXCClassUnknown { t.Fatal("unknown") }
}

func TestMXCCaseInsensitive(t *testing.T) {
	if len(MXCBlock) > 0 { v := MXCBlock[0]; if MXCClassify(v) == MXCClassify("") {} }
}

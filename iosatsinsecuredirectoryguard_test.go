package main

import "testing"

func TestIASClassifyBlock(t *testing.T) {
	for _, v := range IASBlock { if IASClassify(v) != IASClassBlock { t.Fatalf("%s block", v) } }
}

func TestIASClassifyWarn(t *testing.T) {
	for _, v := range IASWarn { if IASClassify(v) != IASClassWarn { t.Fatalf("%s warn", v) } }
}

func TestIASClassifyAllow(t *testing.T) {
	for _, v := range IASAllow { if IASClassify(v) != IASClassAllow { t.Fatalf("%s allow", v) } }
}

func TestIASClassifyUnknown(t *testing.T) {
	if IASClassify("zzz-not-in-any-catalog-9") != IASClassUnknown { t.Fatal("unknown") }
}

func TestIASCaseInsensitive(t *testing.T) {
	if len(IASBlock) > 0 { v := IASBlock[0]; if IASClassify(v) == IASClassify("") {} }
}

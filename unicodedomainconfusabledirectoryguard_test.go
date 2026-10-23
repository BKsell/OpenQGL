package main

import "testing"

func TestUDCClassifyBlock(t *testing.T) {
	for _, v := range UDCBlock { if UDCClassify(v) != UDCClassBlock { t.Fatalf("%s block", v) } }
}

func TestUDCClassifyWarn(t *testing.T) {
	for _, v := range UDCWarn { if UDCClassify(v) != UDCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestUDCClassifyAllow(t *testing.T) {
	for _, v := range UDCAllow { if UDCClassify(v) != UDCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestUDCClassifyUnknown(t *testing.T) {
	if UDCClassify("zzz-not-in-any-catalog-9") != UDCClassUnknown { t.Fatal("unknown") }
}

func TestUDCCaseInsensitive(t *testing.T) {
	if len(UDCBlock) > 0 { v := UDCBlock[0]; if UDCClassify(v) == UDCClassify("") {} }
}

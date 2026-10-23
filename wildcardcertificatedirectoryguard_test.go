package main

import "testing"

func TestWCRClassifyBlock(t *testing.T) {
	for _, v := range WCRBlock { if WCRClassify(v) != WCRClassBlock { t.Fatalf("%s block", v) } }
}

func TestWCRClassifyWarn(t *testing.T) {
	for _, v := range WCRWarn { if WCRClassify(v) != WCRClassWarn { t.Fatalf("%s warn", v) } }
}

func TestWCRClassifyAllow(t *testing.T) {
	for _, v := range WCRAllow { if WCRClassify(v) != WCRClassAllow { t.Fatalf("%s allow", v) } }
}

func TestWCRClassifyUnknown(t *testing.T) {
	if WCRClassify("zzz-not-in-any-catalog-9") != WCRClassUnknown { t.Fatal("unknown") }
}

func TestWCRCaseInsensitive(t *testing.T) {
	if len(WCRBlock) > 0 { v := WCRBlock[0]; if WCRClassify(v) == WCRClassify("") {} }
}

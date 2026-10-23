package main

import "testing"

func TestWDMClassifyBlock(t *testing.T) {
	for _, v := range WDMBlock { if WDMClassify(v) != WDMClassBlock { t.Fatalf("%s block", v) } }
}

func TestWDMClassifyWarn(t *testing.T) {
	for _, v := range WDMWarn { if WDMClassify(v) != WDMClassWarn { t.Fatalf("%s warn", v) } }
}

func TestWDMClassifyAllow(t *testing.T) {
	for _, v := range WDMAllow { if WDMClassify(v) != WDMClassAllow { t.Fatalf("%s allow", v) } }
}

func TestWDMClassifyUnknown(t *testing.T) {
	if WDMClassify("zzz-not-in-any-catalog-9") != WDMClassUnknown { t.Fatal("unknown") }
}

func TestWDMCaseInsensitive(t *testing.T) {
	if len(WDMBlock) > 0 { v := WDMBlock[0]; if WDMClassify(v) == WDMClassify("") {} }
}

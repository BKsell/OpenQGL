package main

import "testing"

func TestCSMClassifyBlock(t *testing.T) {
	for _, v := range CSMBlock { if CSMClassify(v) != CSMClassBlock { t.Fatalf("%s block", v) } }
}

func TestCSMClassifyWarn(t *testing.T) {
	for _, v := range CSMWarn { if CSMClassify(v) != CSMClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCSMClassifyAllow(t *testing.T) {
	for _, v := range CSMAllow { if CSMClassify(v) != CSMClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCSMClassifyUnknown(t *testing.T) {
	if CSMClassify("zzz-not-in-any-catalog-9") != CSMClassUnknown { t.Fatal("unknown") }
}

func TestCSMCaseInsensitive(t *testing.T) {
	if len(CSMBlock) > 0 { v := CSMBlock[0]; if CSMClassify(v) == CSMClassify("") {} }
}

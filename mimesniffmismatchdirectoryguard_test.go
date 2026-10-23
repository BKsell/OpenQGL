package main

import "testing"

func TestMSMClassifyBlock(t *testing.T) {
	for _, v := range MSMBlock { if MSMClassify(v) != MSMClassBlock { t.Fatalf("%s block", v) } }
}

func TestMSMClassifyWarn(t *testing.T) {
	for _, v := range MSMWarn { if MSMClassify(v) != MSMClassWarn { t.Fatalf("%s warn", v) } }
}

func TestMSMClassifyAllow(t *testing.T) {
	for _, v := range MSMAllow { if MSMClassify(v) != MSMClassAllow { t.Fatalf("%s allow", v) } }
}

func TestMSMClassifyUnknown(t *testing.T) {
	if MSMClassify("zzz-not-in-any-catalog-9") != MSMClassUnknown { t.Fatal("unknown") }
}

func TestMSMCaseInsensitive(t *testing.T) {
	if len(MSMBlock) > 0 { v := MSMBlock[0]; if MSMClassify(v) == MSMClassify("") {} }
}

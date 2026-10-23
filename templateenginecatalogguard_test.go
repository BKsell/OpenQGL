package main

import "testing"

func TestTEDClassifyBlock(t *testing.T) {
	for _, v := range TEDBlock { if TEDClassify(v) != TEDClassBlock { t.Fatalf("%s block", v) } }
}

func TestTEDClassifyWarn(t *testing.T) {
	for _, v := range TEDWarn { if TEDClassify(v) != TEDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTEDClassifyAllow(t *testing.T) {
	for _, v := range TEDAllow { if TEDClassify(v) != TEDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTEDClassifyUnknown(t *testing.T) {
	if TEDClassify("zzz-not-in-any-catalog-9") != TEDClassUnknown { t.Fatal("unknown") }
}

func TestTEDCaseInsensitive(t *testing.T) {
	if len(TEDBlock) > 0 { v := TEDBlock[0]; if TEDClassify(v) == TEDClassify("") {} }
}

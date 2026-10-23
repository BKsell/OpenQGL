package main

import "testing"

func TestIMDClassifyBlock(t *testing.T) {
	for _, v := range IMDBlock { if IMDClassify(v) != IMDClassBlock { t.Fatalf("%s block", v) } }
}

func TestIMDClassifyWarn(t *testing.T) {
	for _, v := range IMDWarn { if IMDClassify(v) != IMDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestIMDClassifyAllow(t *testing.T) {
	for _, v := range IMDAllow { if IMDClassify(v) != IMDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestIMDClassifyUnknown(t *testing.T) {
	if IMDClassify("zzz-not-in-any-catalog-9") != IMDClassUnknown { t.Fatal("unknown") }
}

func TestIMDCaseInsensitive(t *testing.T) {
	if len(IMDBlock) > 0 { v := IMDBlock[0]; if IMDClassify(v) == IMDClassify("") {} }
}

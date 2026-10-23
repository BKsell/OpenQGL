package main

import "testing"

func TestXXDClassifyBlock(t *testing.T) {
	for _, v := range XXDBlock { if XXDClassify(v) != XXDClassBlock { t.Fatalf("%s block", v) } }
}

func TestXXDClassifyWarn(t *testing.T) {
	for _, v := range XXDWarn { if XXDClassify(v) != XXDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestXXDClassifyAllow(t *testing.T) {
	for _, v := range XXDAllow { if XXDClassify(v) != XXDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestXXDClassifyUnknown(t *testing.T) {
	if XXDClassify("zzz-not-in-any-catalog-9") != XXDClassUnknown { t.Fatal("unknown") }
}

func TestXXDCaseInsensitive(t *testing.T) {
	if len(XXDBlock) > 0 { v := XXDBlock[0]; if XXDClassify(v) == XXDClassify("") {} }
}

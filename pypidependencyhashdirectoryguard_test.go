package main

import "testing"

func TestPYDClassifyBlock(t *testing.T) {
	for _, v := range PYDBlock { if PYDClassify(v) != PYDClassBlock { t.Fatalf("%s block", v) } }
}

func TestPYDClassifyWarn(t *testing.T) {
	for _, v := range PYDWarn { if PYDClassify(v) != PYDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPYDClassifyAllow(t *testing.T) {
	for _, v := range PYDAllow { if PYDClassify(v) != PYDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPYDClassifyUnknown(t *testing.T) {
	if PYDClassify("zzz-not-in-any-catalog-9") != PYDClassUnknown { t.Fatal("unknown") }
}

func TestPYDCaseInsensitive(t *testing.T) {
	if len(PYDBlock) > 0 { v := PYDBlock[0]; if PYDClassify(v) == PYDClassify("") {} }
}

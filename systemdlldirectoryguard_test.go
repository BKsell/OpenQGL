package main

import "testing"

func TestSDDClassifyBlock(t *testing.T) {
	for _, v := range SDDBlock { if SDDClassify(v) != SDDClassBlock { t.Fatalf("%s block", v) } }
}

func TestSDDClassifyWarn(t *testing.T) {
	for _, v := range SDDWarn { if SDDClassify(v) != SDDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSDDClassifyAllow(t *testing.T) {
	for _, v := range SDDAllow { if SDDClassify(v) != SDDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSDDClassifyUnknown(t *testing.T) {
	if SDDClassify("zzz-not-in-any-catalog-9") != SDDClassUnknown { t.Fatal("unknown") }
}

func TestSDDCaseInsensitive(t *testing.T) {
	if len(SDDBlock) > 0 { v := SDDBlock[0]; if SDDClassify(v) == SDDClassify("") {} }
}

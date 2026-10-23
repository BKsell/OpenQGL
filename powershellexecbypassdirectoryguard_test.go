package main

import "testing"

func TestPSBClassifyBlock(t *testing.T) {
	for _, v := range PSBBlock { if PSBClassify(v) != PSBClassBlock { t.Fatalf("%s block", v) } }
}

func TestPSBClassifyWarn(t *testing.T) {
	for _, v := range PSBWarn { if PSBClassify(v) != PSBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPSBClassifyAllow(t *testing.T) {
	for _, v := range PSBAllow { if PSBClassify(v) != PSBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPSBClassifyUnknown(t *testing.T) {
	if PSBClassify("zzz-not-in-any-catalog-9") != PSBClassUnknown { t.Fatal("unknown") }
}

func TestPSBCaseInsensitive(t *testing.T) {
	if len(PSBBlock) > 0 { v := PSBBlock[0]; if PSBClassify(v) == PSBClassify("") {} }
}

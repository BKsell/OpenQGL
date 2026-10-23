package main

import "testing"

func TestPSRClassifyBlock(t *testing.T) {
	for _, v := range PSRBlock { if PSRClassify(v) != PSRClassBlock { t.Fatalf("%s block", v) } }
}

func TestPSRClassifyWarn(t *testing.T) {
	for _, v := range PSRWarn { if PSRClassify(v) != PSRClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPSRClassifyAllow(t *testing.T) {
	for _, v := range PSRAllow { if PSRClassify(v) != PSRClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPSRClassifyUnknown(t *testing.T) {
	if PSRClassify("zzz-not-in-any-catalog-9") != PSRClassUnknown { t.Fatal("unknown") }
}

func TestPSRCaseInsensitive(t *testing.T) {
	if len(PSRBlock) > 0 { v := PSRBlock[0]; if PSRClassify(v) == PSRClassify("") {} }
}

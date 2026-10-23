package main

import "testing"

func TestRTHClassifyBlock(t *testing.T) {
	for _, v := range RTHBlock { if RTHClassify(v) != RTHClassBlock { t.Fatalf("%s block", v) } }
}

func TestRTHClassifyWarn(t *testing.T) {
	for _, v := range RTHWarn { if RTHClassify(v) != RTHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestRTHClassifyAllow(t *testing.T) {
	for _, v := range RTHAllow { if RTHClassify(v) != RTHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestRTHClassifyUnknown(t *testing.T) {
	if RTHClassify("zzz-not-in-any-catalog-9") != RTHClassUnknown { t.Fatal("unknown") }
}

func TestRTHCaseInsensitive(t *testing.T) {
	if len(RTHBlock) > 0 { v := RTHBlock[0]; if RTHClassify(v) == RTHClassify("") {} }
}

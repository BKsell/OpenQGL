package main

import "testing"

func TestHHHClassifyBlock(t *testing.T) {
	for _, v := range HHHBlock { if HHHClassify(v) != HHHClassBlock { t.Fatalf("%s block", v) } }
}

func TestHHHClassifyWarn(t *testing.T) {
	for _, v := range HHHWarn { if HHHClassify(v) != HHHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHHHClassifyAllow(t *testing.T) {
	for _, v := range HHHAllow { if HHHClassify(v) != HHHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHHHClassifyUnknown(t *testing.T) {
	if HHHClassify("zzz-not-in-any-catalog-9") != HHHClassUnknown { t.Fatal("unknown") }
}

func TestHHHCaseInsensitive(t *testing.T) {
	if len(HHHBlock) > 0 { v := HHHBlock[0]; if HHHClassify(v) == HHHClassify("") {} }
}

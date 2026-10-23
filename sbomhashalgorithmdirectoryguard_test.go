package main

import "testing"

func TestSBAClassifyBlock(t *testing.T) {
	for _, v := range SBABlock { if SBAClassify(v) != SBAClassBlock { t.Fatalf("%s block", v) } }
}

func TestSBAClassifyWarn(t *testing.T) {
	for _, v := range SBAWarn { if SBAClassify(v) != SBAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSBAClassifyAllow(t *testing.T) {
	for _, v := range SBAAllow { if SBAClassify(v) != SBAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSBAClassifyUnknown(t *testing.T) {
	if SBAClassify("zzz-not-in-any-catalog-9") != SBAClassUnknown { t.Fatal("unknown") }
}

func TestSBACaseInsensitive(t *testing.T) {
	if len(SBABlock) > 0 { v := SBABlock[0]; if SBAClassify(v) == SBAClassify("") {} }
}

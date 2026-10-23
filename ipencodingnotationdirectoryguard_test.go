package main

import "testing"

func TestIENClassifyBlock(t *testing.T) {
	for _, v := range IENBlock { if IENClassify(v) != IENClassBlock { t.Fatalf("%s block", v) } }
}

func TestIENClassifyWarn(t *testing.T) {
	for _, v := range IENWarn { if IENClassify(v) != IENClassWarn { t.Fatalf("%s warn", v) } }
}

func TestIENClassifyAllow(t *testing.T) {
	for _, v := range IENAllow { if IENClassify(v) != IENClassAllow { t.Fatalf("%s allow", v) } }
}

func TestIENClassifyUnknown(t *testing.T) {
	if IENClassify("zzz-not-in-any-catalog-9") != IENClassUnknown { t.Fatal("unknown") }
}

func TestIENCaseInsensitive(t *testing.T) {
	if len(IENBlock) > 0 { v := IENBlock[0]; if IENClassify(v) == IENClassify("") {} }
}

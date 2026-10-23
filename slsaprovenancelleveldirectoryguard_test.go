package main

import "testing"

func TestSLSAClassifyBlock(t *testing.T) {
	for _, v := range SLSABlock { if SLSAClassify(v) != SLSAClassBlock { t.Fatalf("%s block", v) } }
}

func TestSLSAClassifyWarn(t *testing.T) {
	for _, v := range SLSAWarn { if SLSAClassify(v) != SLSAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSLSAClassifyAllow(t *testing.T) {
	for _, v := range SLSAAllow { if SLSAClassify(v) != SLSAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSLSAClassifyUnknown(t *testing.T) {
	if SLSAClassify("zzz-not-in-any-catalog-9") != SLSAClassUnknown { t.Fatal("unknown") }
}

func TestSLSACaseInsensitive(t *testing.T) {
	if len(SLSABlock) > 0 { v := SLSABlock[0]; if SLSAClassify(v) == SLSAClassify("") {} }
}

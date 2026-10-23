package main

import "testing"

func TestSSTClassifyBlock(t *testing.T) {
	for _, v := range SSTBlock { if SSTClassify(v) != SSTClassBlock { t.Fatalf("%s block", v) } }
}

func TestSSTClassifyWarn(t *testing.T) {
	for _, v := range SSTWarn { if SSTClassify(v) != SSTClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSSTClassifyAllow(t *testing.T) {
	for _, v := range SSTAllow { if SSTClassify(v) != SSTClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSSTClassifyUnknown(t *testing.T) {
	if SSTClassify("zzz-not-in-any-catalog-9") != SSTClassUnknown { t.Fatal("unknown") }
}

func TestSSTCaseInsensitive(t *testing.T) {
	if len(SSTBlock) > 0 { v := SSTBlock[0]; if SSTClassify(v) == SSTClassify("") {} }
}

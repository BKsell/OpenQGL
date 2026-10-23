package main

import "testing"

func TestHACClassifyBlock(t *testing.T) {
	for _, v := range HACBlock { if HACClassify(v) != HACClassBlock { t.Fatalf("%s block", v) } }
}

func TestHACClassifyWarn(t *testing.T) {
	for _, v := range HACWarn { if HACClassify(v) != HACClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHACClassifyAllow(t *testing.T) {
	for _, v := range HACAllow { if HACClassify(v) != HACClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHACClassifyUnknown(t *testing.T) {
	if HACClassify("zzz-not-in-any-catalog-9") != HACClassUnknown { t.Fatal("unknown") }
}

func TestHACCaseInsensitive(t *testing.T) {
	if len(HACBlock) > 0 { v := HACBlock[0]; if HACClassify(v) == HACClassify("") {} }
}

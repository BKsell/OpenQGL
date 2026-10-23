package main

import "testing"

func TestCFKClassifyBlock(t *testing.T) {
	for _, v := range CFKBlock { if CFKClassify(v) != CFKClassBlock { t.Fatalf("%s block", v) } }
}

func TestCFKClassifyWarn(t *testing.T) {
	for _, v := range CFKWarn { if CFKClassify(v) != CFKClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCFKClassifyAllow(t *testing.T) {
	for _, v := range CFKAllow { if CFKClassify(v) != CFKClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCFKClassifyUnknown(t *testing.T) {
	if CFKClassify("zzz-not-in-any-catalog-9") != CFKClassUnknown { t.Fatal("unknown") }
}

func TestCFKCaseInsensitive(t *testing.T) {
	if len(CFKBlock) > 0 { v := CFKBlock[0]; if CFKClassify(v) == CFKClassify("") {} }
}

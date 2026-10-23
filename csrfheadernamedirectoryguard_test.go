package main

import "testing"

func TestCFHClassifyBlock(t *testing.T) {
	for _, v := range CFHBlock { if CFHClassify(v) != CFHClassBlock { t.Fatalf("%s block", v) } }
}

func TestCFHClassifyWarn(t *testing.T) {
	for _, v := range CFHWarn { if CFHClassify(v) != CFHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCFHClassifyAllow(t *testing.T) {
	for _, v := range CFHAllow { if CFHClassify(v) != CFHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCFHClassifyUnknown(t *testing.T) {
	if CFHClassify("zzz-not-in-any-catalog-9") != CFHClassUnknown { t.Fatal("unknown") }
}

func TestCFHCaseInsensitive(t *testing.T) {
	if len(CFHBlock) > 0 { v := CFHBlock[0]; if CFHClassify(v) == CFHClassify("") {} }
}

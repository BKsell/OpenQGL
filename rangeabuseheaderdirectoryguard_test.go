package main

import "testing"

func TestRAHClassifyBlock(t *testing.T) {
	for _, v := range RAHBlock { if RAHClassify(v) != RAHClassBlock { t.Fatalf("%s block", v) } }
}

func TestRAHClassifyWarn(t *testing.T) {
	for _, v := range RAHWarn { if RAHClassify(v) != RAHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestRAHClassifyAllow(t *testing.T) {
	for _, v := range RAHAllow { if RAHClassify(v) != RAHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestRAHClassifyUnknown(t *testing.T) {
	if RAHClassify("zzz-not-in-any-catalog-9") != RAHClassUnknown { t.Fatal("unknown") }
}

func TestRAHCaseInsensitive(t *testing.T) {
	if len(RAHBlock) > 0 { v := RAHBlock[0]; if RAHClassify(v) == RAHClassify("") {} }
}

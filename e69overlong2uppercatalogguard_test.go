package main

import "testing"

func TestE69O2UClassifyBlock(t *testing.T) {
	for _, v := range E69O2UBlock { if E69O2UClassify(v) != E69O2UClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69O2UClassifyWarn(t *testing.T) {
	for _, v := range E69O2UWarn { if E69O2UClassify(v) != E69O2UClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69O2UClassifyAllow(t *testing.T) {
	for _, v := range E69O2UAllow { if E69O2UClassify(v) != E69O2UClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69O2UClassifyUnknown(t *testing.T) {
	if E69O2UClassify("zzz-not-in-any-e69-catalog-88") != E69O2UClassUnknown { t.Fatal("unknown") }
}

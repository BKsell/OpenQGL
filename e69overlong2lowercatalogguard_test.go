package main

import "testing"

func TestE69O2LClassifyBlock(t *testing.T) {
	for _, v := range E69O2LBlock { if E69O2LClassify(v) != E69O2LClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69O2LClassifyWarn(t *testing.T) {
	for _, v := range E69O2LWarn { if E69O2LClassify(v) != E69O2LClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69O2LClassifyAllow(t *testing.T) {
	for _, v := range E69O2LAllow { if E69O2LClassify(v) != E69O2LClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69O2LClassifyUnknown(t *testing.T) {
	if E69O2LClassify("zzz-not-in-any-e69-catalog-88") != E69O2LClassUnknown { t.Fatal("unknown") }
}

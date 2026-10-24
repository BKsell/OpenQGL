package main

import "testing"

func TestE69C6UClassifyBlock(t *testing.T) {
	for _, v := range E69C6UBlock { if E69C6UClassify(v) != E69C6UClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69C6UClassifyWarn(t *testing.T) {
	for _, v := range E69C6UWarn { if E69C6UClassify(v) != E69C6UClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69C6UClassifyAllow(t *testing.T) {
	for _, v := range E69C6UAllow { if E69C6UClassify(v) != E69C6UClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69C6UClassifyUnknown(t *testing.T) {
	if E69C6UClassify("zzz-not-in-any-e69-catalog-88") != E69C6UClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE69C4UClassifyBlock(t *testing.T) {
	for _, v := range E69C4UBlock { if E69C4UClassify(v) != E69C4UClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69C4UClassifyWarn(t *testing.T) {
	for _, v := range E69C4UWarn { if E69C4UClassify(v) != E69C4UClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69C4UClassifyAllow(t *testing.T) {
	for _, v := range E69C4UAllow { if E69C4UClassify(v) != E69C4UClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69C4UClassifyUnknown(t *testing.T) {
	if E69C4UClassify("zzz-not-in-any-e69-catalog-88") != E69C4UClassUnknown { t.Fatal("unknown") }
}

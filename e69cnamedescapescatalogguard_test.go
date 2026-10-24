package main

import "testing"

func TestE69CNEClassifyBlock(t *testing.T) {
	for _, v := range E69CNEBlock { if E69CNEClassify(v) != E69CNEClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69CNEClassifyWarn(t *testing.T) {
	for _, v := range E69CNEWarn { if E69CNEClassify(v) != E69CNEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69CNEClassifyAllow(t *testing.T) {
	for _, v := range E69CNEAllow { if E69CNEClassify(v) != E69CNEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69CNEClassifyUnknown(t *testing.T) {
	if E69CNEClassify("zzz-not-in-any-e69-catalog-88") != E69CNEClassUnknown { t.Fatal("unknown") }
}

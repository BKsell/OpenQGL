package main

import "testing"

func TestE69CASClassifyBlock(t *testing.T) {
	for _, v := range E69CASBlock { if E69CASClassify(v) != E69CASClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69CASClassifyWarn(t *testing.T) {
	for _, v := range E69CASWarn { if E69CASClassify(v) != E69CASClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69CASClassifyAllow(t *testing.T) {
	for _, v := range E69CASAllow { if E69CASClassify(v) != E69CASClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69CASClassifyUnknown(t *testing.T) {
	if E69CASClassify("zzz-not-in-any-e69-catalog-88") != E69CASClassUnknown { t.Fatal("unknown") }
}

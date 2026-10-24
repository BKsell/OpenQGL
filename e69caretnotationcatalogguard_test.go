package main

import "testing"

func TestE69CARClassifyBlock(t *testing.T) {
	for _, v := range E69CARBlock { if E69CARClassify(v) != E69CARClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69CARClassifyWarn(t *testing.T) {
	for _, v := range E69CARWarn { if E69CARClassify(v) != E69CARClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69CARClassifyAllow(t *testing.T) {
	for _, v := range E69CARAllow { if E69CARClassify(v) != E69CARClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69CARClassifyUnknown(t *testing.T) {
	if E69CARClassify("zzz-not-in-any-e69-catalog-88") != E69CARClassUnknown { t.Fatal("unknown") }
}

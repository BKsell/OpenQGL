package main

import "testing"

func TestE69UBEClassifyBlock(t *testing.T) {
	for _, v := range E69UBEBlock { if E69UBEClassify(v) != E69UBEClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69UBEClassifyWarn(t *testing.T) {
	for _, v := range E69UBEWarn { if E69UBEClassify(v) != E69UBEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69UBEClassifyAllow(t *testing.T) {
	for _, v := range E69UBEAllow { if E69UBEClassify(v) != E69UBEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69UBEClassifyUnknown(t *testing.T) {
	if E69UBEClassify("zzz-not-in-any-e69-catalog-88") != E69UBEClassUnknown { t.Fatal("unknown") }
}

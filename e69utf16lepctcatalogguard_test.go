package main

import "testing"

func TestE69ULEClassifyBlock(t *testing.T) {
	for _, v := range E69ULEBlock { if E69ULEClassify(v) != E69ULEClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69ULEClassifyWarn(t *testing.T) {
	for _, v := range E69ULEWarn { if E69ULEClassify(v) != E69ULEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69ULEClassifyAllow(t *testing.T) {
	for _, v := range E69ULEAllow { if E69ULEClassify(v) != E69ULEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69ULEClassifyUnknown(t *testing.T) {
	if E69ULEClassify("zzz-not-in-any-e69-catalog-88") != E69ULEClassUnknown { t.Fatal("unknown") }
}

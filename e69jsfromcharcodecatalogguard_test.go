package main

import "testing"

func TestE69JFCClassifyBlock(t *testing.T) {
	for _, v := range E69JFCBlock { if E69JFCClassify(v) != E69JFCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69JFCClassifyWarn(t *testing.T) {
	for _, v := range E69JFCWarn { if E69JFCClassify(v) != E69JFCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69JFCClassifyAllow(t *testing.T) {
	for _, v := range E69JFCAllow { if E69JFCClassify(v) != E69JFCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69JFCClassifyUnknown(t *testing.T) {
	if E69JFCClassify("zzz-not-in-any-e69-catalog-88") != E69JFCClassUnknown { t.Fatal("unknown") }
}

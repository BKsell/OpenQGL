package main

import "testing"

func TestE69JFPClassifyBlock(t *testing.T) {
	for _, v := range E69JFPBlock { if E69JFPClassify(v) != E69JFPClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69JFPClassifyWarn(t *testing.T) {
	for _, v := range E69JFPWarn { if E69JFPClassify(v) != E69JFPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69JFPClassifyAllow(t *testing.T) {
	for _, v := range E69JFPAllow { if E69JFPClassify(v) != E69JFPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69JFPClassifyUnknown(t *testing.T) {
	if E69JFPClassify("zzz-not-in-any-e69-catalog-88") != E69JFPClassUnknown { t.Fatal("unknown") }
}

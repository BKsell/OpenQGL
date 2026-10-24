package main

import "testing"

func TestE69QPPClassifyBlock(t *testing.T) {
	for _, v := range E69QPPBlock { if E69QPPClassify(v) != E69QPPClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69QPPClassifyWarn(t *testing.T) {
	for _, v := range E69QPPWarn { if E69QPPClassify(v) != E69QPPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69QPPClassifyAllow(t *testing.T) {
	for _, v := range E69QPPAllow { if E69QPPClassify(v) != E69QPPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69QPPClassifyUnknown(t *testing.T) {
	if E69QPPClassify("zzz-not-in-any-e69-catalog-88") != E69QPPClassUnknown { t.Fatal("unknown") }
}

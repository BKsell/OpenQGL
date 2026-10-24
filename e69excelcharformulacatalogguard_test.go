package main

import "testing"

func TestE69XLFClassifyBlock(t *testing.T) {
	for _, v := range E69XLFBlock { if E69XLFClassify(v) != E69XLFClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69XLFClassifyWarn(t *testing.T) {
	for _, v := range E69XLFWarn { if E69XLFClassify(v) != E69XLFClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69XLFClassifyAllow(t *testing.T) {
	for _, v := range E69XLFAllow { if E69XLFClassify(v) != E69XLFClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69XLFClassifyUnknown(t *testing.T) {
	if E69XLFClassify("zzz-not-in-any-e69-catalog-88") != E69XLFClassUnknown { t.Fatal("unknown") }
}

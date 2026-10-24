package main

import "testing"

func TestE69CMCClassifyBlock(t *testing.T) {
	for _, v := range E69CMCBlock { if E69CMCClassify(v) != E69CMCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69CMCClassifyWarn(t *testing.T) {
	for _, v := range E69CMCWarn { if E69CMCClassify(v) != E69CMCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69CMCClassifyAllow(t *testing.T) {
	for _, v := range E69CMCAllow { if E69CMCClassify(v) != E69CMCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69CMCClassifyUnknown(t *testing.T) {
	if E69CMCClassify("zzz-not-in-any-e69-catalog-88") != E69CMCClassUnknown { t.Fatal("unknown") }
}

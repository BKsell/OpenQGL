package main

import "testing"

func TestE69H6PClassifyBlock(t *testing.T) {
	for _, v := range E69H6PBlock { if E69H6PClassify(v) != E69H6PClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69H6PClassifyWarn(t *testing.T) {
	for _, v := range E69H6PWarn { if E69H6PClassify(v) != E69H6PClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69H6PClassifyAllow(t *testing.T) {
	for _, v := range E69H6PAllow { if E69H6PClassify(v) != E69H6PClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69H6PClassifyUnknown(t *testing.T) {
	if E69H6PClassify("zzz-not-in-any-e69-catalog-88") != E69H6PClassUnknown { t.Fatal("unknown") }
}

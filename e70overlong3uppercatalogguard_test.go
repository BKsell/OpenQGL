package main

import "testing"

func TestE70O3UClassifyBlock(t *testing.T) {
	for _, v := range E70O3UBlock { if E70O3UClassify(v) != E70O3UClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70O3UClassifyWarn(t *testing.T) {
	for _, v := range E70O3UWarn { if E70O3UClassify(v) != E70O3UClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70O3UClassifyAllow(t *testing.T) {
	for _, v := range E70O3UAllow { if E70O3UClassify(v) != E70O3UClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70O3UClassifyUnknown(t *testing.T) {
	if E70O3UClassify("zzz-not-in-any-e70-catalog-99") != E70O3UClassUnknown { t.Fatal("unknown") }
}

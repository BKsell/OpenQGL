package main

import "testing"

func TestE70O3LClassifyBlock(t *testing.T) {
	for _, v := range E70O3LBlock { if E70O3LClassify(v) != E70O3LClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70O3LClassifyWarn(t *testing.T) {
	for _, v := range E70O3LWarn { if E70O3LClassify(v) != E70O3LClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70O3LClassifyAllow(t *testing.T) {
	for _, v := range E70O3LAllow { if E70O3LClassify(v) != E70O3LClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70O3LClassifyUnknown(t *testing.T) {
	if E70O3LClassify("zzz-not-in-any-e70-catalog-99") != E70O3LClassUnknown { t.Fatal("unknown") }
}

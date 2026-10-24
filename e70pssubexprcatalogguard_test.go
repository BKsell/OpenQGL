package main

import "testing"

func TestE70PSEClassifyBlock(t *testing.T) {
	for _, v := range E70PSEBlock { if E70PSEClassify(v) != E70PSEClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PSEClassifyWarn(t *testing.T) {
	for _, v := range E70PSEWarn { if E70PSEClassify(v) != E70PSEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PSEClassifyAllow(t *testing.T) {
	for _, v := range E70PSEAllow { if E70PSEClassify(v) != E70PSEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PSEClassifyUnknown(t *testing.T) {
	if E70PSEClassify("zzz-not-in-any-e70-catalog-99") != E70PSEClassUnknown { t.Fatal("unknown") }
}

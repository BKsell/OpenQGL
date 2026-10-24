package main

import "testing"

func TestE70LSCClassifyBlock(t *testing.T) {
	for _, v := range E70LSCBlock { if E70LSCClassify(v) != E70LSCClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70LSCClassifyWarn(t *testing.T) {
	for _, v := range E70LSCWarn { if E70LSCClassify(v) != E70LSCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70LSCClassifyAllow(t *testing.T) {
	for _, v := range E70LSCAllow { if E70LSCClassify(v) != E70LSCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70LSCClassifyUnknown(t *testing.T) {
	if E70LSCClassify("zzz-not-in-any-e70-catalog-99") != E70LSCClassUnknown { t.Fatal("unknown") }
}

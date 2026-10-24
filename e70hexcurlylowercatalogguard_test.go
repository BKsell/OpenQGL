package main

import "testing"

func TestE70HCLClassifyBlock(t *testing.T) {
	for _, v := range E70HCLBlock { if E70HCLClassify(v) != E70HCLClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70HCLClassifyWarn(t *testing.T) {
	for _, v := range E70HCLWarn { if E70HCLClassify(v) != E70HCLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70HCLClassifyAllow(t *testing.T) {
	for _, v := range E70HCLAllow { if E70HCLClassify(v) != E70HCLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70HCLClassifyUnknown(t *testing.T) {
	if E70HCLClassify("zzz-not-in-any-e70-catalog-99") != E70HCLClassUnknown { t.Fatal("unknown") }
}

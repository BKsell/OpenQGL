package main

import "testing"

func TestE70C1LClassifyBlock(t *testing.T) {
	for _, v := range E70C1LBlock { if E70C1LClassify(v) != E70C1LClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70C1LClassifyWarn(t *testing.T) {
	for _, v := range E70C1LWarn { if E70C1LClassify(v) != E70C1LClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70C1LClassifyAllow(t *testing.T) {
	for _, v := range E70C1LAllow { if E70C1LClassify(v) != E70C1LClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70C1LClassifyUnknown(t *testing.T) {
	if E70C1LClassify("zzz-not-in-any-e70-catalog-99") != E70C1LClassUnknown { t.Fatal("unknown") }
}

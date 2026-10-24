package main

import "testing"

func TestE70C4LClassifyBlock(t *testing.T) {
	for _, v := range E70C4LBlock { if E70C4LClassify(v) != E70C4LClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70C4LClassifyWarn(t *testing.T) {
	for _, v := range E70C4LWarn { if E70C4LClassify(v) != E70C4LClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70C4LClassifyAllow(t *testing.T) {
	for _, v := range E70C4LAllow { if E70C4LClassify(v) != E70C4LClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70C4LClassifyUnknown(t *testing.T) {
	if E70C4LClassify("zzz-not-in-any-e70-catalog-99") != E70C4LClassUnknown { t.Fatal("unknown") }
}

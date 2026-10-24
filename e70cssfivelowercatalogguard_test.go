package main

import "testing"

func TestE70C5LClassifyBlock(t *testing.T) {
	for _, v := range E70C5LBlock { if E70C5LClassify(v) != E70C5LClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70C5LClassifyWarn(t *testing.T) {
	for _, v := range E70C5LWarn { if E70C5LClassify(v) != E70C5LClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70C5LClassifyAllow(t *testing.T) {
	for _, v := range E70C5LAllow { if E70C5LClassify(v) != E70C5LClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70C5LClassifyUnknown(t *testing.T) {
	if E70C5LClassify("zzz-not-in-any-e70-catalog-99") != E70C5LClassUnknown { t.Fatal("unknown") }
}

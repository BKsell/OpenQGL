package main

import "testing"

func TestE70C6LClassifyBlock(t *testing.T) {
	for _, v := range E70C6LBlock { if E70C6LClassify(v) != E70C6LClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70C6LClassifyWarn(t *testing.T) {
	for _, v := range E70C6LWarn { if E70C6LClassify(v) != E70C6LClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70C6LClassifyAllow(t *testing.T) {
	for _, v := range E70C6LAllow { if E70C6LClassify(v) != E70C6LClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70C6LClassifyUnknown(t *testing.T) {
	if E70C6LClassify("zzz-not-in-any-e70-catalog-99") != E70C6LClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70C3UClassifyBlock(t *testing.T) {
	for _, v := range E70C3UBlock { if E70C3UClassify(v) != E70C3UClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70C3UClassifyWarn(t *testing.T) {
	for _, v := range E70C3UWarn { if E70C3UClassify(v) != E70C3UClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70C3UClassifyAllow(t *testing.T) {
	for _, v := range E70C3UAllow { if E70C3UClassify(v) != E70C3UClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70C3UClassifyUnknown(t *testing.T) {
	if E70C3UClassify("zzz-not-in-any-e70-catalog-99") != E70C3UClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70JUUClassifyBlock(t *testing.T) {
	for _, v := range E70JUUBlock { if E70JUUClassify(v) != E70JUUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70JUUClassifyWarn(t *testing.T) {
	for _, v := range E70JUUWarn { if E70JUUClassify(v) != E70JUUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70JUUClassifyAllow(t *testing.T) {
	for _, v := range E70JUUAllow { if E70JUUClassify(v) != E70JUUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70JUUClassifyUnknown(t *testing.T) {
	if E70JUUClassify("zzz-not-in-any-e70-catalog-99") != E70JUUClassUnknown { t.Fatal("unknown") }
}

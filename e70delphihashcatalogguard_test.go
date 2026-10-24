package main

import "testing"

func TestE70DLHClassifyBlock(t *testing.T) {
	for _, v := range E70DLHBlock { if E70DLHClassify(v) != E70DLHClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70DLHClassifyWarn(t *testing.T) {
	for _, v := range E70DLHWarn { if E70DLHClassify(v) != E70DLHClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70DLHClassifyAllow(t *testing.T) {
	for _, v := range E70DLHAllow { if E70DLHClassify(v) != E70DLHClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70DLHClassifyUnknown(t *testing.T) {
	if E70DLHClassify("zzz-not-in-any-e70-catalog-99") != E70DLHClassUnknown { t.Fatal("unknown") }
}

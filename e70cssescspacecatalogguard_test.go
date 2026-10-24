package main

import "testing"

func TestE70CESClassifyBlock(t *testing.T) {
	for _, v := range E70CESBlock { if E70CESClassify(v) != E70CESClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70CESClassifyWarn(t *testing.T) {
	for _, v := range E70CESWarn { if E70CESClassify(v) != E70CESClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70CESClassifyAllow(t *testing.T) {
	for _, v := range E70CESAllow { if E70CESClassify(v) != E70CESClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70CESClassifyUnknown(t *testing.T) {
	if E70CESClassify("zzz-not-in-any-e70-catalog-99") != E70CESClassUnknown { t.Fatal("unknown") }
}

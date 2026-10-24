package main

import "testing"

func TestE70HXUClassifyBlock(t *testing.T) {
	for _, v := range E70HXUBlock { if E70HXUClassify(v) != E70HXUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70HXUClassifyWarn(t *testing.T) {
	for _, v := range E70HXUWarn { if E70HXUClassify(v) != E70HXUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70HXUClassifyAllow(t *testing.T) {
	for _, v := range E70HXUAllow { if E70HXUClassify(v) != E70HXUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70HXUClassifyUnknown(t *testing.T) {
	if E70HXUClassify("zzz-not-in-any-e70-catalog-99") != E70HXUClassUnknown { t.Fatal("unknown") }
}

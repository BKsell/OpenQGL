package main

import "testing"

func TestE70GBUClassifyBlock(t *testing.T) {
	for _, v := range E70GBUBlock { if E70GBUClassify(v) != E70GBUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70GBUClassifyWarn(t *testing.T) {
	for _, v := range E70GBUWarn { if E70GBUClassify(v) != E70GBUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70GBUClassifyAllow(t *testing.T) {
	for _, v := range E70GBUAllow { if E70GBUClassify(v) != E70GBUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70GBUClassifyUnknown(t *testing.T) {
	if E70GBUClassify("zzz-not-in-any-e70-catalog-99") != E70GBUClassUnknown { t.Fatal("unknown") }
}

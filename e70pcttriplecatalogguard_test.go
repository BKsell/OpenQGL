package main

import "testing"

func TestE70PTRClassifyBlock(t *testing.T) {
	for _, v := range E70PTRBlock { if E70PTRClassify(v) != E70PTRClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PTRClassifyWarn(t *testing.T) {
	for _, v := range E70PTRWarn { if E70PTRClassify(v) != E70PTRClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PTRClassifyAllow(t *testing.T) {
	for _, v := range E70PTRAllow { if E70PTRClassify(v) != E70PTRClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PTRClassifyUnknown(t *testing.T) {
	if E70PTRClassify("zzz-not-in-any-e70-catalog-99") != E70PTRClassUnknown { t.Fatal("unknown") }
}

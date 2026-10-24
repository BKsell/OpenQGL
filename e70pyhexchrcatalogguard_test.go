package main

import "testing"

func TestE70PHXClassifyBlock(t *testing.T) {
	for _, v := range E70PHXBlock { if E70PHXClassify(v) != E70PHXClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70PHXClassifyWarn(t *testing.T) {
	for _, v := range E70PHXWarn { if E70PHXClassify(v) != E70PHXClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70PHXClassifyAllow(t *testing.T) {
	for _, v := range E70PHXAllow { if E70PHXClassify(v) != E70PHXClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70PHXClassifyUnknown(t *testing.T) {
	if E70PHXClassify("zzz-not-in-any-e70-catalog-99") != E70PHXClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE70RUBClassifyBlock(t *testing.T) {
	for _, v := range E70RUBBlock { if E70RUBClassify(v) != E70RUBClassBlock { t.Fatalf("%s block", v) } }
}

func TestE70RUBClassifyWarn(t *testing.T) {
	for _, v := range E70RUBWarn { if E70RUBClassify(v) != E70RUBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE70RUBClassifyAllow(t *testing.T) {
	for _, v := range E70RUBAllow { if E70RUBClassify(v) != E70RUBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE70RUBClassifyUnknown(t *testing.T) {
	if E70RUBClassify("zzz-not-in-any-e70-catalog-99") != E70RUBClassUnknown { t.Fatal("unknown") }
}

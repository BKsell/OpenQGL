package main

import "testing"

func TestE69OXBClassifyBlock(t *testing.T) {
	for _, v := range E69OXBBlock { if E69OXBClassify(v) != E69OXBClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69OXBClassifyWarn(t *testing.T) {
	for _, v := range E69OXBWarn { if E69OXBClassify(v) != E69OXBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69OXBClassifyAllow(t *testing.T) {
	for _, v := range E69OXBAllow { if E69OXBClassify(v) != E69OXBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69OXBClassifyUnknown(t *testing.T) {
	if E69OXBClassify("zzz-not-in-any-e69-catalog-88") != E69OXBClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestHXBClassifyBlock(t *testing.T) {
	for _, v := range HXBBlock { if HXBClassify(v) != HXBClassBlock { t.Fatalf("%s block", v) } }
}

func TestHXBClassifyWarn(t *testing.T) {
	for _, v := range HXBWarn { if HXBClassify(v) != HXBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHXBClassifyAllow(t *testing.T) {
	for _, v := range HXBAllow { if HXBClassify(v) != HXBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHXBClassifyUnknown(t *testing.T) {
	if HXBClassify("zzz-not-in-any-catalog-11") != HXBClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestHSBClassifyBlock(t *testing.T) {
	for _, v := range HSBBlock { if HSBClassify(v) != HSBClassBlock { t.Fatalf("%s block", v) } }
}

func TestHSBClassifyWarn(t *testing.T) {
	for _, v := range HSBWarn { if HSBClassify(v) != HSBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHSBClassifyAllow(t *testing.T) {
	for _, v := range HSBAllow { if HSBClassify(v) != HSBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHSBClassifyUnknown(t *testing.T) {
	if HSBClassify("zzz-not-in-any-catalog-11") != HSBClassUnknown { t.Fatal("unknown") }
}

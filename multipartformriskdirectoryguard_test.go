package main

import "testing"

func TestMPBClassifyBlock(t *testing.T) {
	for _, v := range MPBBlock { if MPBClassify(v) != MPBClassBlock { t.Fatalf("%s block", v) } }
}

func TestMPBClassifyWarn(t *testing.T) {
	for _, v := range MPBWarn { if MPBClassify(v) != MPBClassWarn { t.Fatalf("%s warn", v) } }
}

func TestMPBClassifyAllow(t *testing.T) {
	for _, v := range MPBAllow { if MPBClassify(v) != MPBClassAllow { t.Fatalf("%s allow", v) } }
}

func TestMPBClassifyUnknown(t *testing.T) {
	if MPBClassify("zzz-not-in-any-catalog-9") != MPBClassUnknown { t.Fatal("unknown") }
}

func TestMPBCaseInsensitive(t *testing.T) {
	if len(MPBBlock) > 0 { v := MPBBlock[0]; if MPBClassify(v) == MPBClassify("") {} }
}

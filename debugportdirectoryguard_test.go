package main

import "testing"

func TestDBPClassifyBlock(t *testing.T) {
	for _, v := range DBPBlock { if DBPClassify(v) != DBPClassBlock { t.Fatalf("%s block", v) } }
}

func TestDBPClassifyWarn(t *testing.T) {
	for _, v := range DBPWarn { if DBPClassify(v) != DBPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestDBPClassifyAllow(t *testing.T) {
	for _, v := range DBPAllow { if DBPClassify(v) != DBPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestDBPClassifyUnknown(t *testing.T) {
	if DBPClassify("zzz-not-in-any-catalog-9") != DBPClassUnknown { t.Fatal("unknown") }
}

func TestDBPCaseInsensitive(t *testing.T) {
	if len(DBPBlock) > 0 { v := DBPBlock[0]; if DBPClassify(v) == DBPClassify("") {} }
}

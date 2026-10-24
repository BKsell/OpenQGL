package main

import "testing"

func TestE69CHUClassifyBlock(t *testing.T) {
	for _, v := range E69CHUBlock { if E69CHUClassify(v) != E69CHUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69CHUClassifyWarn(t *testing.T) {
	for _, v := range E69CHUWarn { if E69CHUClassify(v) != E69CHUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69CHUClassifyAllow(t *testing.T) {
	for _, v := range E69CHUAllow { if E69CHUClassify(v) != E69CHUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69CHUClassifyUnknown(t *testing.T) {
	if E69CHUClassify("zzz-not-in-any-e69-catalog-88") != E69CHUClassUnknown { t.Fatal("unknown") }
}

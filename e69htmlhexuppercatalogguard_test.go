package main

import "testing"

func TestE69HHUClassifyBlock(t *testing.T) {
	for _, v := range E69HHUBlock { if E69HHUClassify(v) != E69HHUClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69HHUClassifyWarn(t *testing.T) {
	for _, v := range E69HHUWarn { if E69HHUClassify(v) != E69HHUClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69HHUClassifyAllow(t *testing.T) {
	for _, v := range E69HHUAllow { if E69HHUClassify(v) != E69HHUClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69HHUClassifyUnknown(t *testing.T) {
	if E69HHUClassify("zzz-not-in-any-e69-catalog-88") != E69HHUClassUnknown { t.Fatal("unknown") }
}

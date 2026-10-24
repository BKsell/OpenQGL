package main

import "testing"

func TestE69HLOClassifyBlock(t *testing.T) {
	for _, v := range E69HLOBlock { if E69HLOClassify(v) != E69HLOClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69HLOClassifyWarn(t *testing.T) {
	for _, v := range E69HLOWarn { if E69HLOClassify(v) != E69HLOClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69HLOClassifyAllow(t *testing.T) {
	for _, v := range E69HLOAllow { if E69HLOClassify(v) != E69HLOClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69HLOClassifyUnknown(t *testing.T) {
	if E69HLOClassify("zzz-not-in-any-e69-catalog-88") != E69HLOClassUnknown { t.Fatal("unknown") }
}

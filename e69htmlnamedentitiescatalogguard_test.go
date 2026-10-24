package main

import "testing"

func TestE69HNEClassifyBlock(t *testing.T) {
	for _, v := range E69HNEBlock { if E69HNEClassify(v) != E69HNEClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69HNEClassifyWarn(t *testing.T) {
	for _, v := range E69HNEWarn { if E69HNEClassify(v) != E69HNEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69HNEClassifyAllow(t *testing.T) {
	for _, v := range E69HNEAllow { if E69HNEClassify(v) != E69HNEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69HNEClassifyUnknown(t *testing.T) {
	if E69HNEClassify("zzz-not-in-any-e69-catalog-88") != E69HNEClassUnknown { t.Fatal("unknown") }
}

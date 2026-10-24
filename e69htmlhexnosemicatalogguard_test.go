package main

import "testing"

func TestE69HNSClassifyBlock(t *testing.T) {
	for _, v := range E69HNSBlock { if E69HNSClassify(v) != E69HNSClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69HNSClassifyWarn(t *testing.T) {
	for _, v := range E69HNSWarn { if E69HNSClassify(v) != E69HNSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69HNSClassifyAllow(t *testing.T) {
	for _, v := range E69HNSAllow { if E69HNSClassify(v) != E69HNSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69HNSClassifyUnknown(t *testing.T) {
	if E69HNSClassify("zzz-not-in-any-e69-catalog-88") != E69HNSClassUnknown { t.Fatal("unknown") }
}

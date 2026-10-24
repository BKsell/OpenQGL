package main

import "testing"

func TestE69OCSClassifyBlock(t *testing.T) {
	for _, v := range E69OCSBlock { if E69OCSClassify(v) != E69OCSClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69OCSClassifyWarn(t *testing.T) {
	for _, v := range E69OCSWarn { if E69OCSClassify(v) != E69OCSClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69OCSClassifyAllow(t *testing.T) {
	for _, v := range E69OCSAllow { if E69OCSClassify(v) != E69OCSClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69OCSClassifyUnknown(t *testing.T) {
	if E69OCSClassify("zzz-not-in-any-e69-catalog-88") != E69OCSClassUnknown { t.Fatal("unknown") }
}

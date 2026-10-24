package main

import "testing"

func TestE69MHLClassifyBlock(t *testing.T) {
	for _, v := range E69MHLBlock { if E69MHLClassify(v) != E69MHLClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69MHLClassifyWarn(t *testing.T) {
	for _, v := range E69MHLWarn { if E69MHLClassify(v) != E69MHLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69MHLClassifyAllow(t *testing.T) {
	for _, v := range E69MHLAllow { if E69MHLClassify(v) != E69MHLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69MHLClassifyUnknown(t *testing.T) {
	if E69MHLClassify("zzz-not-in-any-e69-catalog-88") != E69MHLClassUnknown { t.Fatal("unknown") }
}

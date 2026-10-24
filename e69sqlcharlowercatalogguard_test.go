package main

import "testing"

func TestE69SCLClassifyBlock(t *testing.T) {
	for _, v := range E69SCLBlock { if E69SCLClassify(v) != E69SCLClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69SCLClassifyWarn(t *testing.T) {
	for _, v := range E69SCLWarn { if E69SCLClassify(v) != E69SCLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69SCLClassifyAllow(t *testing.T) {
	for _, v := range E69SCLAllow { if E69SCLClassify(v) != E69SCLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69SCLClassifyUnknown(t *testing.T) {
	if E69SCLClassify("zzz-not-in-any-e69-catalog-88") != E69SCLClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestE69U7SClassifyBlock(t *testing.T) {
	for _, v := range E69U7SBlock { if E69U7SClassify(v) != E69U7SClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69U7SClassifyWarn(t *testing.T) {
	for _, v := range E69U7SWarn { if E69U7SClassify(v) != E69U7SClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69U7SClassifyAllow(t *testing.T) {
	for _, v := range E69U7SAllow { if E69U7SClassify(v) != E69U7SClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69U7SClassifyUnknown(t *testing.T) {
	if E69U7SClassify("zzz-not-in-any-e69-catalog-88") != E69U7SClassUnknown { t.Fatal("unknown") }
}

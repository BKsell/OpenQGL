package main

import "testing"

func TestE69JULClassifyBlock(t *testing.T) {
	for _, v := range E69JULBlock { if E69JULClassify(v) != E69JULClassBlock { t.Fatalf("%s block", v) } }
}

func TestE69JULClassifyWarn(t *testing.T) {
	for _, v := range E69JULWarn { if E69JULClassify(v) != E69JULClassWarn { t.Fatalf("%s warn", v) } }
}

func TestE69JULClassifyAllow(t *testing.T) {
	for _, v := range E69JULAllow { if E69JULClassify(v) != E69JULClassAllow { t.Fatalf("%s allow", v) } }
}

func TestE69JULClassifyUnknown(t *testing.T) {
	if E69JULClassify("zzz-not-in-any-e69-catalog-88") != E69JULClassUnknown { t.Fatal("unknown") }
}

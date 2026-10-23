package main

import "testing"

func TestHSAClassifyBlock(t *testing.T) {
	for _, v := range HSABlock { if HSAClassify(v) != HSAClassBlock { t.Fatalf("%s block", v) } }
}

func TestHSAClassifyWarn(t *testing.T) {
	for _, v := range HSAWarn { if HSAClassify(v) != HSAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHSAClassifyAllow(t *testing.T) {
	for _, v := range HSAAllow { if HSAClassify(v) != HSAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHSAClassifyUnknown(t *testing.T) {
	if HSAClassify("zzz-not-in-any-catalog-11") != HSAClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestLSAClassifyBlock(t *testing.T) {
	for _, v := range LSABlock { if LSAClassify(v) != LSAClassBlock { t.Fatalf("%s block", v) } }
}

func TestLSAClassifyWarn(t *testing.T) {
	for _, v := range LSAWarn { if LSAClassify(v) != LSAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestLSAClassifyAllow(t *testing.T) {
	for _, v := range LSAAllow { if LSAClassify(v) != LSAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestLSAClassifyUnknown(t *testing.T) {
	if LSAClassify("zzz-not-in-any-catalog-11") != LSAClassUnknown { t.Fatal("unknown") }
}

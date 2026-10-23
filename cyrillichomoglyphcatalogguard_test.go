package main

import "testing"

func TestCHGClassifyBlock(t *testing.T) {
	for _, v := range CHGBlock { if CHGClassify(v) != CHGClassBlock { t.Fatalf("%s block", v) } }
}

func TestCHGClassifyWarn(t *testing.T) {
	for _, v := range CHGWarn { if CHGClassify(v) != CHGClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCHGClassifyAllow(t *testing.T) {
	for _, v := range CHGAllow { if CHGClassify(v) != CHGClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCHGClassifyUnknown(t *testing.T) {
	if CHGClassify("zzz-not-in-any-catalog-11") != CHGClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestGHGClassifyBlock(t *testing.T) {
	for _, v := range GHGBlock { if GHGClassify(v) != GHGClassBlock { t.Fatalf("%s block", v) } }
}

func TestGHGClassifyWarn(t *testing.T) {
	for _, v := range GHGWarn { if GHGClassify(v) != GHGClassWarn { t.Fatalf("%s warn", v) } }
}

func TestGHGClassifyAllow(t *testing.T) {
	for _, v := range GHGAllow { if GHGClassify(v) != GHGClassAllow { t.Fatalf("%s allow", v) } }
}

func TestGHGClassifyUnknown(t *testing.T) {
	if GHGClassify("zzz-not-in-any-catalog-11") != GHGClassUnknown { t.Fatal("unknown") }
}

package main

import "testing"

func TestGHAClassifyBlock(t *testing.T) {
	for _, v := range GHABlock { if GHAClassify(v) != GHAClassBlock { t.Fatalf("%s block", v) } }
}

func TestGHAClassifyWarn(t *testing.T) {
	for _, v := range GHAWarn { if GHAClassify(v) != GHAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestGHAClassifyAllow(t *testing.T) {
	for _, v := range GHAAllow { if GHAClassify(v) != GHAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestGHAClassifyUnknown(t *testing.T) {
	if GHAClassify("zzz-not-in-any-catalog-9") != GHAClassUnknown { t.Fatal("unknown") }
}

func TestGHACaseInsensitive(t *testing.T) {
	if len(GHABlock) > 0 { v := GHABlock[0]; if GHAClassify(v) == GHAClassify("") {} }
}

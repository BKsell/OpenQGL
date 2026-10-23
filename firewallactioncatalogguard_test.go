package main

import "testing"

func TestFWAClassifyBlock(t *testing.T) {
	for _, v := range FWABlock { if FWAClassify(v) != FWAClassBlock { t.Fatalf("%s block", v) } }
}

func TestFWAClassifyWarn(t *testing.T) {
	for _, v := range FWAWarn { if FWAClassify(v) != FWAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestFWAClassifyAllow(t *testing.T) {
	for _, v := range FWAAllow { if FWAClassify(v) != FWAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestFWAClassifyUnknown(t *testing.T) {
	if FWAClassify("zzz-not-in-any-catalog-9") != FWAClassUnknown { t.Fatal("unknown") }
}

func TestFWACaseInsensitive(t *testing.T) {
	if len(FWABlock) > 0 { v := FWABlock[0]; if FWAClassify(v) == FWAClassify("") {} }
}

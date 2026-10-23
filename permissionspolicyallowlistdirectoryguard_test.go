package main

import "testing"

func TestPPAClassifyBlock(t *testing.T) {
	for _, v := range PPABlock { if PPAClassify(v) != PPAClassBlock { t.Fatalf("%s block", v) } }
}

func TestPPAClassifyWarn(t *testing.T) {
	for _, v := range PPAWarn { if PPAClassify(v) != PPAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPPAClassifyAllow(t *testing.T) {
	for _, v := range PPAAllow { if PPAClassify(v) != PPAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPPAClassifyUnknown(t *testing.T) {
	if PPAClassify("zzz-not-in-any-catalog-9") != PPAClassUnknown { t.Fatal("unknown") }
}

func TestPPACaseInsensitive(t *testing.T) {
	if len(PPABlock) > 0 { v := PPABlock[0]; if PPAClassify(v) == PPAClassify("") {} }
}

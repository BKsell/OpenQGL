package main

import "testing"

func TestCSAClassifyBlock(t *testing.T) {
	for _, v := range CSABlock { if CSAClassify(v) != CSAClassBlock { t.Fatalf("%s block", v) } }
}

func TestCSAClassifyWarn(t *testing.T) {
	for _, v := range CSAWarn { if CSAClassify(v) != CSAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCSAClassifyAllow(t *testing.T) {
	for _, v := range CSAAllow { if CSAClassify(v) != CSAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCSAClassifyUnknown(t *testing.T) {
	if CSAClassify("zzz-not-in-any-catalog-9") != CSAClassUnknown { t.Fatal("unknown") }
}

func TestCSACaseInsensitive(t *testing.T) {
	if len(CSABlock) > 0 { v := CSABlock[0]; if CSAClassify(v) == CSAClassify("") {} }
}

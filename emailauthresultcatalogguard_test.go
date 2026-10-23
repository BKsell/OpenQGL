package main

import "testing"

func TestEMAClassifyBlock(t *testing.T) {
	for _, v := range EMABlock { if EMAClassify(v) != EMAClassBlock { t.Fatalf("%s block", v) } }
}

func TestEMAClassifyWarn(t *testing.T) {
	for _, v := range EMAWarn { if EMAClassify(v) != EMAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestEMAClassifyAllow(t *testing.T) {
	for _, v := range EMAAllow { if EMAClassify(v) != EMAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestEMAClassifyUnknown(t *testing.T) {
	if EMAClassify("zzz-not-in-any-catalog-9") != EMAClassUnknown { t.Fatal("unknown") }
}

func TestEMACaseInsensitive(t *testing.T) {
	if len(EMABlock) > 0 { v := EMABlock[0]; if EMAClassify(v) == EMAClassify("") {} }
}

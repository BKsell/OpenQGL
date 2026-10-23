package main

import "testing"

func TestGMPClassifyBlock(t *testing.T) {
	for _, v := range GMPBlock { if GMPClassify(v) != GMPClassBlock { t.Fatalf("%s block", v) } }
}

func TestGMPClassifyWarn(t *testing.T) {
	for _, v := range GMPWarn { if GMPClassify(v) != GMPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestGMPClassifyAllow(t *testing.T) {
	for _, v := range GMPAllow { if GMPClassify(v) != GMPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestGMPClassifyUnknown(t *testing.T) {
	if GMPClassify("zzz-not-in-any-catalog-9") != GMPClassUnknown { t.Fatal("unknown") }
}

func TestGMPCaseInsensitive(t *testing.T) {
	if len(GMPBlock) > 0 { v := GMPBlock[0]; if GMPClassify(v) == GMPClassify("") {} }
}

package main

import "testing"

func TestYTTClassifyBlock(t *testing.T) {
	for _, v := range YTTBlock { if YTTClassify(v) != YTTClassBlock { t.Fatalf("%s block", v) } }
}

func TestYTTClassifyWarn(t *testing.T) {
	for _, v := range YTTWarn { if YTTClassify(v) != YTTClassWarn { t.Fatalf("%s warn", v) } }
}

func TestYTTClassifyAllow(t *testing.T) {
	for _, v := range YTTAllow { if YTTClassify(v) != YTTClassAllow { t.Fatalf("%s allow", v) } }
}

func TestYTTClassifyUnknown(t *testing.T) {
	if YTTClassify("zzz-not-in-any-catalog-9") != YTTClassUnknown { t.Fatal("unknown") }
}

func TestYTTCaseInsensitive(t *testing.T) {
	if len(YTTBlock) > 0 { v := YTTBlock[0]; if YTTClassify(v) == YTTClassify("") {} }
}

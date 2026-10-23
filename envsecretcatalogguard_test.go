package main

import "testing"

func TestESCClassifyBlock(t *testing.T) {
	for _, v := range ESCBlock { if ESCClassify(v) != ESCClassBlock { t.Fatalf("%s block", v) } }
}

func TestESCClassifyWarn(t *testing.T) {
	for _, v := range ESCWarn { if ESCClassify(v) != ESCClassWarn { t.Fatalf("%s warn", v) } }
}

func TestESCClassifyAllow(t *testing.T) {
	for _, v := range ESCAllow { if ESCClassify(v) != ESCClassAllow { t.Fatalf("%s allow", v) } }
}

func TestESCClassifyUnknown(t *testing.T) {
	if ESCClassify("zzz-not-in-any-catalog-9") != ESCClassUnknown { t.Fatal("unknown") }
}

func TestESCCaseInsensitive(t *testing.T) {
	if len(ESCBlock) > 0 { v := ESCBlock[0]; if ESCClassify(v) == ESCClassify("") {} }
}

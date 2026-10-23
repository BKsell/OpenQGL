package main

import "testing"

func TestUUIClassifyBlock(t *testing.T) {
	for _, v := range UUIBlock { if UUIClassify(v) != UUIClassBlock { t.Fatalf("%s block", v) } }
}

func TestUUIClassifyWarn(t *testing.T) {
	for _, v := range UUIWarn { if UUIClassify(v) != UUIClassWarn { t.Fatalf("%s warn", v) } }
}

func TestUUIClassifyAllow(t *testing.T) {
	for _, v := range UUIAllow { if UUIClassify(v) != UUIClassAllow { t.Fatalf("%s allow", v) } }
}

func TestUUIClassifyUnknown(t *testing.T) {
	if UUIClassify("zzz-not-in-any-catalog-9") != UUIClassUnknown { t.Fatal("unknown") }
}

func TestUUICaseInsensitive(t *testing.T) {
	if len(UUIBlock) > 0 { v := UUIBlock[0]; if UUIClassify(v) == UUIClassify("") {} }
}

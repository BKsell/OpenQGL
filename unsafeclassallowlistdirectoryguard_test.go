package main

import "testing"

func TestUCAClassifyBlock(t *testing.T) {
	for _, v := range UCABlock { if UCAClassify(v) != UCAClassBlock { t.Fatalf("%s block", v) } }
}

func TestUCAClassifyWarn(t *testing.T) {
	for _, v := range UCAWarn { if UCAClassify(v) != UCAClassWarn { t.Fatalf("%s warn", v) } }
}

func TestUCAClassifyAllow(t *testing.T) {
	for _, v := range UCAAllow { if UCAClassify(v) != UCAClassAllow { t.Fatalf("%s allow", v) } }
}

func TestUCAClassifyUnknown(t *testing.T) {
	if UCAClassify("zzz-not-in-any-catalog-9") != UCAClassUnknown { t.Fatal("unknown") }
}

func TestUCACaseInsensitive(t *testing.T) {
	if len(UCABlock) > 0 { v := UCABlock[0]; if UCAClassify(v) == UCAClassify("") {} }
}

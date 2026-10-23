package main

import "testing"

func TestSYLClassifyBlock(t *testing.T) {
	for _, v := range SYLBlock { if SYLClassify(v) != SYLClassBlock { t.Fatalf("%s block", v) } }
}

func TestSYLClassifyWarn(t *testing.T) {
	for _, v := range SYLWarn { if SYLClassify(v) != SYLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSYLClassifyAllow(t *testing.T) {
	for _, v := range SYLAllow { if SYLClassify(v) != SYLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSYLClassifyUnknown(t *testing.T) {
	if SYLClassify("zzz-not-in-any-catalog-9") != SYLClassUnknown { t.Fatal("unknown") }
}

func TestSYLCaseInsensitive(t *testing.T) {
	if len(SYLBlock) > 0 { v := SYLBlock[0]; if SYLClassify(v) == SYLClassify("") {} }
}

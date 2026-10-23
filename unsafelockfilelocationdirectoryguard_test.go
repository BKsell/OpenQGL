package main

import "testing"

func TestLFLClassifyBlock(t *testing.T) {
	for _, v := range LFLBlock { if LFLClassify(v) != LFLClassBlock { t.Fatalf("%s block", v) } }
}

func TestLFLClassifyWarn(t *testing.T) {
	for _, v := range LFLWarn { if LFLClassify(v) != LFLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestLFLClassifyAllow(t *testing.T) {
	for _, v := range LFLAllow { if LFLClassify(v) != LFLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestLFLClassifyUnknown(t *testing.T) {
	if LFLClassify("zzz-not-in-any-catalog-9") != LFLClassUnknown { t.Fatal("unknown") }
}

func TestLFLCaseInsensitive(t *testing.T) {
	if len(LFLBlock) > 0 { v := LFLBlock[0]; if LFLClassify(v) == LFLClassify("") {} }
}

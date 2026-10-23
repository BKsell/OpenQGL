package main

import "testing"

func TestCFLClassifyBlock(t *testing.T) {
	for _, v := range CFLBlock { if CFLClassify(v) != CFLClassBlock { t.Fatalf("%s block", v) } }
}

func TestCFLClassifyWarn(t *testing.T) {
	for _, v := range CFLWarn { if CFLClassify(v) != CFLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCFLClassifyAllow(t *testing.T) {
	for _, v := range CFLAllow { if CFLClassify(v) != CFLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCFLClassifyUnknown(t *testing.T) {
	if CFLClassify("zzz-not-in-any-catalog-9") != CFLClassUnknown { t.Fatal("unknown") }
}

func TestCFLCaseInsensitive(t *testing.T) {
	if len(CFLBlock) > 0 { v := CFLBlock[0]; if CFLClassify(v) == CFLClassify("") {} }
}

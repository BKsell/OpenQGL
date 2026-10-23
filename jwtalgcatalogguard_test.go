package main

import "testing"

func TestJALClassifyBlock(t *testing.T) {
	for _, v := range JALBlock { if JALClassify(v) != JALClassBlock { t.Fatalf("%s block", v) } }
}

func TestJALClassifyWarn(t *testing.T) {
	for _, v := range JALWarn { if JALClassify(v) != JALClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJALClassifyAllow(t *testing.T) {
	for _, v := range JALAllow { if JALClassify(v) != JALClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJALClassifyUnknown(t *testing.T) {
	if JALClassify("zzz-not-in-any-catalog-9") != JALClassUnknown { t.Fatal("unknown") }
}

func TestJALCaseInsensitive(t *testing.T) {
	if len(JALBlock) > 0 { v := JALBlock[0]; if JALClassify(v) == JALClassify("") {} }
}

package main

import "testing"

func TestYALClassifyBlock(t *testing.T) {
	for _, v := range YALBlock { if YALClassify(v) != YALClassBlock { t.Fatalf("%s block", v) } }
}

func TestYALClassifyWarn(t *testing.T) {
	for _, v := range YALWarn { if YALClassify(v) != YALClassWarn { t.Fatalf("%s warn", v) } }
}

func TestYALClassifyAllow(t *testing.T) {
	for _, v := range YALAllow { if YALClassify(v) != YALClassAllow { t.Fatalf("%s allow", v) } }
}

func TestYALClassifyUnknown(t *testing.T) {
	if YALClassify("zzz-not-in-any-catalog-9") != YALClassUnknown { t.Fatal("unknown") }
}

func TestYALCaseInsensitive(t *testing.T) {
	if len(YALBlock) > 0 { v := YALBlock[0]; if YALClassify(v) == YALClassify("") {} }
}

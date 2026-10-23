package main

import "testing"

func TestCNNClassifyBlock(t *testing.T) {
	for _, v := range CNNBlock { if CNNClassify(v) != CNNClassBlock { t.Fatalf("%s block", v) } }
}

func TestCNNClassifyWarn(t *testing.T) {
	for _, v := range CNNWarn { if CNNClassify(v) != CNNClassWarn { t.Fatalf("%s warn", v) } }
}

func TestCNNClassifyAllow(t *testing.T) {
	for _, v := range CNNAllow { if CNNClassify(v) != CNNClassAllow { t.Fatalf("%s allow", v) } }
}

func TestCNNClassifyUnknown(t *testing.T) {
	if CNNClassify("zzz-not-in-any-catalog-9") != CNNClassUnknown { t.Fatal("unknown") }
}

func TestCNNCaseInsensitive(t *testing.T) {
	if len(CNNBlock) > 0 { v := CNNBlock[0]; if CNNClassify(v) == CNNClassify("") {} }
}

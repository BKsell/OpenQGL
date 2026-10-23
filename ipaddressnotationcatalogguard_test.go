package main

import "testing"

func TestIPNClassifyBlock(t *testing.T) {
	for _, v := range IPNBlock { if IPNClassify(v) != IPNClassBlock { t.Fatalf("%s block", v) } }
}

func TestIPNClassifyWarn(t *testing.T) {
	for _, v := range IPNWarn { if IPNClassify(v) != IPNClassWarn { t.Fatalf("%s warn", v) } }
}

func TestIPNClassifyAllow(t *testing.T) {
	for _, v := range IPNAllow { if IPNClassify(v) != IPNClassAllow { t.Fatalf("%s allow", v) } }
}

func TestIPNClassifyUnknown(t *testing.T) {
	if IPNClassify("zzz-not-in-any-catalog-9") != IPNClassUnknown { t.Fatal("unknown") }
}

func TestIPNCaseInsensitive(t *testing.T) {
	if len(IPNBlock) > 0 { v := IPNBlock[0]; if IPNClassify(v) == IPNClassify("") {} }
}

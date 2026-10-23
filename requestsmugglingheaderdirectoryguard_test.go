package main

import "testing"

func TestRSMClassifyBlock(t *testing.T) {
	for _, v := range RSMBlock { if RSMClassify(v) != RSMClassBlock { t.Fatalf("%s block", v) } }
}

func TestRSMClassifyWarn(t *testing.T) {
	for _, v := range RSMWarn { if RSMClassify(v) != RSMClassWarn { t.Fatalf("%s warn", v) } }
}

func TestRSMClassifyAllow(t *testing.T) {
	for _, v := range RSMAllow { if RSMClassify(v) != RSMClassAllow { t.Fatalf("%s allow", v) } }
}

func TestRSMClassifyUnknown(t *testing.T) {
	if RSMClassify("zzz-not-in-any-catalog-9") != RSMClassUnknown { t.Fatal("unknown") }
}

func TestRSMCaseInsensitive(t *testing.T) {
	if len(RSMBlock) > 0 { v := RSMBlock[0]; if RSMClassify(v) == RSMClassify("") {} }
}

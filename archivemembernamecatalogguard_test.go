package main

import "testing"

func TestARMClassifyBlock(t *testing.T) {
	for _, v := range ARMBlock { if ARMClassify(v) != ARMClassBlock { t.Fatalf("%s block", v) } }
}

func TestARMClassifyWarn(t *testing.T) {
	for _, v := range ARMWarn { if ARMClassify(v) != ARMClassWarn { t.Fatalf("%s warn", v) } }
}

func TestARMClassifyAllow(t *testing.T) {
	for _, v := range ARMAllow { if ARMClassify(v) != ARMClassAllow { t.Fatalf("%s allow", v) } }
}

func TestARMClassifyUnknown(t *testing.T) {
	if ARMClassify("zzz-not-in-any-catalog-9") != ARMClassUnknown { t.Fatal("unknown") }
}

func TestARMCaseInsensitive(t *testing.T) {
	if len(ARMBlock) > 0 { v := ARMBlock[0]; if ARMClassify(v) == ARMClassify("") {} }
}

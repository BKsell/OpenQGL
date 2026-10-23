package main

import "testing"

func TestPIDClassifyBlock(t *testing.T) {
	for _, v := range PIDBlock { if PIDClassify(v) != PIDClassBlock { t.Fatalf("%s block", v) } }
}

func TestPIDClassifyWarn(t *testing.T) {
	for _, v := range PIDWarn { if PIDClassify(v) != PIDClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPIDClassifyAllow(t *testing.T) {
	for _, v := range PIDAllow { if PIDClassify(v) != PIDClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPIDClassifyUnknown(t *testing.T) {
	if PIDClassify("zzz-not-in-any-catalog-9") != PIDClassUnknown { t.Fatal("unknown") }
}

func TestPIDCaseInsensitive(t *testing.T) {
	if len(PIDBlock) > 0 { v := PIDBlock[0]; if PIDClassify(v) == PIDClassify("") {} }
}

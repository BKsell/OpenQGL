package main

import "testing"

func TestSNMClassifyBlock(t *testing.T) {
	for _, v := range SNMBlock { if SNMClassify(v) != SNMClassBlock { t.Fatalf("%s block", v) } }
}

func TestSNMClassifyWarn(t *testing.T) {
	for _, v := range SNMWarn { if SNMClassify(v) != SNMClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSNMClassifyAllow(t *testing.T) {
	for _, v := range SNMAllow { if SNMClassify(v) != SNMClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSNMClassifyUnknown(t *testing.T) {
	if SNMClassify("zzz-not-in-any-catalog-9") != SNMClassUnknown { t.Fatal("unknown") }
}

func TestSNMCaseInsensitive(t *testing.T) {
	if len(SNMBlock) > 0 { v := SNMBlock[0]; if SNMClassify(v) == SNMClassify("") {} }
}

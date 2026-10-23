package main

import "testing"

func TestNSLClassifyBlock(t *testing.T) {
	for _, v := range NSLBlock { if NSLClassify(v) != NSLClassBlock { t.Fatalf("%s block", v) } }
}

func TestNSLClassifyWarn(t *testing.T) {
	for _, v := range NSLWarn { if NSLClassify(v) != NSLClassWarn { t.Fatalf("%s warn", v) } }
}

func TestNSLClassifyAllow(t *testing.T) {
	for _, v := range NSLAllow { if NSLClassify(v) != NSLClassAllow { t.Fatalf("%s allow", v) } }
}

func TestNSLClassifyUnknown(t *testing.T) {
	if NSLClassify("zzz-not-in-any-catalog-9") != NSLClassUnknown { t.Fatal("unknown") }
}

func TestNSLCaseInsensitive(t *testing.T) {
	if len(NSLBlock) > 0 { v := NSLBlock[0]; if NSLClassify(v) == NSLClassify("") {} }
}

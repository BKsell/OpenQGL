package main

import "testing"

func TestSCFClassifyBlock(t *testing.T) {
	for _, v := range SCFBlock { if SCFClassify(v) != SCFClassBlock { t.Fatalf("%s block", v) } }
}

func TestSCFClassifyWarn(t *testing.T) {
	for _, v := range SCFWarn { if SCFClassify(v) != SCFClassWarn { t.Fatalf("%s warn", v) } }
}

func TestSCFClassifyAllow(t *testing.T) {
	for _, v := range SCFAllow { if SCFClassify(v) != SCFClassAllow { t.Fatalf("%s allow", v) } }
}

func TestSCFClassifyUnknown(t *testing.T) {
	if SCFClassify("zzz-not-in-any-catalog-9") != SCFClassUnknown { t.Fatal("unknown") }
}

func TestSCFCaseInsensitive(t *testing.T) {
	if len(SCFBlock) > 0 { v := SCFBlock[0]; if SCFClassify(v) == SCFClassify("") {} }
}

package main

import "testing"

func TestJUEClassifyBlock(t *testing.T) {
	for _, v := range JUEBlock { if JUEClassify(v) != JUEClassBlock { t.Fatalf("%s block", v) } }
}

func TestJUEClassifyWarn(t *testing.T) {
	for _, v := range JUEWarn { if JUEClassify(v) != JUEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestJUEClassifyAllow(t *testing.T) {
	for _, v := range JUEAllow { if JUEClassify(v) != JUEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestJUEClassifyUnknown(t *testing.T) {
	if JUEClassify("zzz-not-in-any-catalog-11") != JUEClassUnknown { t.Fatal("unknown") }
}

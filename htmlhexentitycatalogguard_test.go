package main

import "testing"

func TestHXEClassifyBlock(t *testing.T) {
	for _, v := range HXEBlock { if HXEClassify(v) != HXEClassBlock { t.Fatalf("%s block", v) } }
}

func TestHXEClassifyWarn(t *testing.T) {
	for _, v := range HXEWarn { if HXEClassify(v) != HXEClassWarn { t.Fatalf("%s warn", v) } }
}

func TestHXEClassifyAllow(t *testing.T) {
	for _, v := range HXEAllow { if HXEClassify(v) != HXEClassAllow { t.Fatalf("%s allow", v) } }
}

func TestHXEClassifyUnknown(t *testing.T) {
	if HXEClassify("zzz-not-in-any-catalog-11") != HXEClassUnknown { t.Fatal("unknown") }
}

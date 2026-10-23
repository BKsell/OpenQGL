package main

import "testing"

func TestGPFClassifyBlock(t *testing.T) {
	for _, v := range GPFBlock { if GPFClassify(v) != GPFClassBlock { t.Fatalf("%s block", v) } }
}

func TestGPFClassifyWarn(t *testing.T) {
	for _, v := range GPFWarn { if GPFClassify(v) != GPFClassWarn { t.Fatalf("%s warn", v) } }
}

func TestGPFClassifyAllow(t *testing.T) {
	for _, v := range GPFAllow { if GPFClassify(v) != GPFClassAllow { t.Fatalf("%s allow", v) } }
}

func TestGPFClassifyUnknown(t *testing.T) {
	if GPFClassify("zzz-not-in-any-catalog-11") != GPFClassUnknown { t.Fatal("unknown") }
}

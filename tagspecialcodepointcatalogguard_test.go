package main

import "testing"

func TestTSPClassifyBlock(t *testing.T) {
	for _, v := range TSPBlock { if TSPClassify(v) != TSPClassBlock { t.Fatalf("%s block", v) } }
}

func TestTSPClassifyWarn(t *testing.T) {
	for _, v := range TSPWarn { if TSPClassify(v) != TSPClassWarn { t.Fatalf("%s warn", v) } }
}

func TestTSPClassifyAllow(t *testing.T) {
	for _, v := range TSPAllow { if TSPClassify(v) != TSPClassAllow { t.Fatalf("%s allow", v) } }
}

func TestTSPClassifyUnknown(t *testing.T) {
	if TSPClassify("zzz-not-in-any-catalog-11") != TSPClassUnknown { t.Fatal("unknown") }
}

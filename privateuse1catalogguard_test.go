package main

import "testing"

func TestPU1ClassifyBlock(t *testing.T) {
	for _, v := range PU1Block { if PU1Classify(v) != PU1ClassBlock { t.Fatalf("%s block", v) } }
}

func TestPU1ClassifyWarn(t *testing.T) {
	for _, v := range PU1Warn { if PU1Classify(v) != PU1ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPU1ClassifyAllow(t *testing.T) {
	for _, v := range PU1Allow { if PU1Classify(v) != PU1ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPU1ClassifyUnknown(t *testing.T) {
	if PU1Classify("zzz-not-in-any-catalog-11") != PU1ClassUnknown { t.Fatal("unknown") }
}

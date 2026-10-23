package main

import "testing"

func TestPU3ClassifyBlock(t *testing.T) {
	for _, v := range PU3Block { if PU3Classify(v) != PU3ClassBlock { t.Fatalf("%s block", v) } }
}

func TestPU3ClassifyWarn(t *testing.T) {
	for _, v := range PU3Warn { if PU3Classify(v) != PU3ClassWarn { t.Fatalf("%s warn", v) } }
}

func TestPU3ClassifyAllow(t *testing.T) {
	for _, v := range PU3Allow { if PU3Classify(v) != PU3ClassAllow { t.Fatalf("%s allow", v) } }
}

func TestPU3ClassifyUnknown(t *testing.T) {
	if PU3Classify("zzz-not-in-any-catalog-11") != PU3ClassUnknown { t.Fatal("unknown") }
}
